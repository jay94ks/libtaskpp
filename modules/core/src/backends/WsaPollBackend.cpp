// Windows readiness backend over select() (sockets only, see DESIGN.md §5 option 1).
// Compiled only on Windows; POSIX builds use epoll / poll instead.
#include <taskpp/core/MonitorBackend.hpp>

#if defined(TASKPP_PLATFORM_WINDOWS)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdio>
#include <mutex>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace taskpp {
namespace {

std::system_error wsaError(const char* what, int code) {
    return std::system_error(code, std::system_category(), what);
}

std::system_error lastWsaError(const char* what) {
    return wsaError(what, ::WSAGetLastError());
}

struct WsaInit {
    WsaInit() {
        WSADATA data { };
        if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw lastWsaError("WSAStartup");
        }
    }
    ~WsaInit() { ::WSACleanup(); }
};

WsaInit& wsaInit() {
    static WsaInit init;
    return init;
}

// A loopback TCP pair used to wake a blocking select(), mirroring the
// eventfd / self-pipe trick of the POSIX backends.
struct WakeupPair {
    SOCKET readSocket = INVALID_SOCKET;
    SOCKET writeSocket = INVALID_SOCKET;

    WakeupPair() {
        (void) wsaInit();

        SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) {
            throw lastWsaError("socket");
        }

        sockaddr_in addr { };
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            auto e = lastWsaError("bind");
            ::closesocket(listener);
            throw e;
        }
        if (::listen(listener, 1) == SOCKET_ERROR) {
            auto e = lastWsaError("listen");
            ::closesocket(listener);
            throw e;
        }

        int len = sizeof(addr);
        if (::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len) == SOCKET_ERROR) {
            auto e = lastWsaError("getsockname");
            ::closesocket(listener);
            throw e;
        }

        // Blocking connect: loopback handshake completes immediately.
        SOCKET writer = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (writer == INVALID_SOCKET) {
            auto e = lastWsaError("socket");
            ::closesocket(listener);
            throw e;
        }

        if (::connect(writer, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            auto e = lastWsaError("connect");
            ::closesocket(writer);
            ::closesocket(listener);
            throw e;
        }

        SOCKET reader = ::accept(listener, nullptr, nullptr);
        ::closesocket(listener);
        if (reader == INVALID_SOCKET) {
            auto e = lastWsaError("accept");
            ::closesocket(writer);
            throw e;
        }

        // Non-blocking: wakeup() never blocks, drain never blocks.
        u_long on = 1;
        ::ioctlsocket(reader, FIONBIO, &on);
        ::ioctlsocket(writer, FIONBIO, &on);

        readSocket = reader;
        writeSocket = writer;
    }

    ~WakeupPair() {
        if (readSocket != INVALID_SOCKET) {
            ::closesocket(readSocket);
        }
        if (writeSocket != INVALID_SOCKET) {
            ::closesocket(writeSocket);
        }
    }

    WakeupPair(const WakeupPair&) = delete;
    WakeupPair& operator=(const WakeupPair&) = delete;
};

class SelectBackend final : public MonitorBackend {
public:
    SelectBackend() {
        (void) wsaInit();
    }

    const char* name() const noexcept override { return "select"; }

    void update(IoFd fd, int /*oldEvents*/, int newEvents) override {
        {
            std::lock_guard lock(mutex_);
            const auto socket = static_cast<SOCKET>(fd);
            if (newEvents) {
                interest_[socket] = newEvents;
            }
            else {
                interest_.erase(socket);
            }
        }
        wakeup();
    }

    void poll(std::vector<IoEventInfo>& out, int timeoutMs) override {
        // Snapshot interest so select() runs without holding the lock.
        std::vector<std::pair<SOCKET, int>> snapshot;
        {
            std::lock_guard lock(mutex_);
            snapshot.reserve(interest_.size());
            for (const auto& [socket, events] : interest_) {
                snapshot.emplace_back(socket, events);
            }
        }

        fd_set readSet, writeSet, exceptSet;
        FD_ZERO(&readSet);
        FD_ZERO(&writeSet);
        FD_ZERO(&exceptSet);
        FD_SET(wakeup_.readSocket, &readSet);
        for (const auto& [socket, events] : snapshot) {
            if (events & IoRead) {
                FD_SET(socket, &readSet);
            }
            if (events & IoWrite) {
                FD_SET(socket, &writeSet);
            }
            FD_SET(socket, &exceptSet);
        }

        timeval tv { };
        timeval* tvp = nullptr;
        if (timeoutMs >= 0) {
            tv.tv_sec = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;
            tvp = &tv;
        }

        const int n = ::select(0, &readSet, &writeSet, &exceptSet, tvp);
        if (n == SOCKET_ERROR) {
            const int code = ::WSAGetLastError();
            if (code == WSAEINTR) {
                return;
            }
            // A closed socket in the set reports WSAENOTSOCK; the monitor
            // re-arms on the next update, so report nothing this round.
            if (code == WSAENOTSOCK) {
                return;
            }
            throw wsaError("select", code);
        }
        if (n == 0) {
            return;
        }

        if (FD_ISSET(wakeup_.readSocket, &readSet)) {
            char buffer[64];
            for (;;) {
                const int r = ::recv(wakeup_.readSocket, buffer, sizeof(buffer), 0);
                if (r <= 0) {
                    break;
                }
            }
        }

        for (const auto& [socket, wanted] : snapshot) {
            int events = 0;
            if (FD_ISSET(socket, &readSet) && (wanted & IoRead)) {
                events |= IoRead;
            }
            // Writable sockets are also often reported readable; only report
            // what was asked for.
            if (FD_ISSET(socket, &writeSet) && (wanted & IoWrite)) {
                events |= IoWrite;
            }
            if (FD_ISSET(socket, &exceptSet)) {
                events |= IoError;
            }
            if (events) {
                out.push_back({ static_cast<IoFd>(socket), events });
            }
        }

        // A peer shutdown on TCP shows up as readable; if a subsequent recv
        // would return 0 the caller sees FD_READ and discovers EOF itself.
        // Report hangup when a read-watched socket is readable but the
        // except set also fired (RST), already covered above.
    }

    void wakeup() noexcept override {
        const char one = 1;
        ::send(wakeup_.writeSocket, &one, 1, 0);
    }

private:
    WakeupPair wakeup_;
    std::mutex mutex_;
    std::unordered_map<SOCKET, int> interest_;
};

} // namespace

std::unique_ptr<MonitorBackend> MonitorBackend::createWsaPoll() {
    return std::make_unique<SelectBackend>();
}

std::unique_ptr<MonitorBackend> MonitorBackend::createDefault() {
    return createWsaPoll();
}

} // namespace taskpp

#endif // TASKPP_PLATFORM_WINDOWS
