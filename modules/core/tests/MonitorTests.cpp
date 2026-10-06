#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <atomic>
#include <chrono>
#include <thread>

#if defined(TASKPP_PLATFORM_WINDOWS) && !defined(TASKPP_PLATFORM_POSIX)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#endif

using namespace taskpp;

namespace {

#if defined(TASKPP_PLATFORM_WINDOWS) && !defined(TASKPP_PLATFORM_POSIX)

struct WsaScope {
    WsaScope() {
        WSADATA data { };
        if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("WSAStartup");
        }
    }
    ~WsaScope() { ::WSACleanup(); }
};

// Loopback TCP pair: reader/writer sockets for tests (sockets only on Windows).
struct Pipe {
    IoFd r = -1, w = -1;
    SOCKET listener = INVALID_SOCKET;

    Pipe() {
        static WsaScope scope;
        (void) scope;
        listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) {
            throw std::runtime_error("socket");
        }
        sockaddr_in addr { };
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR ||
            ::listen(listener, 1) == SOCKET_ERROR) {
            ::closesocket(listener);
            throw std::runtime_error("bind/listen");
        }
        int len = sizeof(addr);
        ::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len);
        SOCKET writer = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (writer == INVALID_SOCKET) {
            ::closesocket(listener);
            throw std::runtime_error("socket");
        }
        if (::connect(writer, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            ::closesocket(writer);
            ::closesocket(listener);
            throw std::runtime_error("connect");
        }
        SOCKET reader = ::accept(listener, nullptr, nullptr);
        if (reader == INVALID_SOCKET) {
            ::closesocket(writer);
            ::closesocket(listener);
            throw std::runtime_error("accept");
        }
        u_long on = 1;
        ::ioctlsocket(reader, FIONBIO, &on);
        ::ioctlsocket(writer, FIONBIO, &on);
        r = static_cast<IoFd>(reader);
        w = static_cast<IoFd>(writer);
    }

    ~Pipe() {
        if (r >= 0) {
            ::closesocket(static_cast<SOCKET>(r));
        }
        if (w >= 0) {
            ::closesocket(static_cast<SOCKET>(w));
        }
        if (listener != INVALID_SOCKET) {
            ::closesocket(listener);
        }
    }

    void write(char c = 'x') const {
        ::send(static_cast<SOCKET>(w), &c, 1, 0);
    }

    int readSome(char* buffer, int size) const {
        return ::recv(static_cast<SOCKET>(r), buffer, size, 0);
    }

    void closeWriter() {
        if (w >= 0) {
            ::closesocket(static_cast<SOCKET>(w));
            w = -1;
        }
    }
};

#else

struct Pipe {
    IoFd r = -1, w = -1;

    Pipe() {
        int fds[2];
        if (::pipe(fds) != 0) {
            throw std::runtime_error("pipe");
        }
        r = fds[0];
        w = fds[1];
        ::fcntl(static_cast<int>(r), F_SETFL, O_NONBLOCK);
        ::fcntl(static_cast<int>(w), F_SETFL, O_NONBLOCK);
    }

    ~Pipe() {
        if (r >= 0) {
            ::close(static_cast<int>(r));
        }
        if (w >= 0) {
            ::close(static_cast<int>(w));
        }
    }

    void write(char c = 'x') const { [[maybe_unused]] auto n = ::write(static_cast<int>(w), &c, 1); }

    int readSome(char* buffer, int size) const {
        return static_cast<int>(::read(static_cast<int>(r), buffer, static_cast<std::size_t>(size)));
    }

    void closeWriter() {
        if (w >= 0) {
            ::close(static_cast<int>(w));
            w = -1;
        }
    }
};

#endif

Task<int> waitReadable(Monitor* monitor, IoFd fd, Canceller ct) {
    int e = co_await monitor->watch(fd, FD_READ, ct);
    co_return e;
}

Task<std::vector<IoEventInfo>> waitAny(Monitor* monitor, std::vector<IoFd> fds) {
    co_return co_await monitor->watchAny(fds, FD_READ);
}

Task<long> echoLoop(Monitor* monitor, const Pipe* pipe, int expected) {
    long received = 0;
    while (received < expected) {
        co_await monitor->watch(pipe->r, FD_READ);
        char buffer[256];
        auto n = pipe->readSome(buffer, sizeof(buffer));
        if (n > 0) {
            received += n;
        }
    }
    co_return received;
}

Task<bool> resumesOnSameWorker(Monitor* monitor, IoFd fd) {
    auto before = Worker::currentWorker();
    co_await monitor->watch(fd, FD_READ);
    co_return before && before == Worker::currentWorker();
}

std::unique_ptr<MonitorBackend> makeBackend(const std::string& name) {
#if defined(TASKPP_PLATFORM_LINUX)
    if (name == "epoll") {
        return MonitorBackend::createEpoll();
    }
#endif
#if defined(TASKPP_PLATFORM_POSIX)
    if (name == "poll") {
        return MonitorBackend::createPoll();
    }
#endif
#if defined(TASKPP_PLATFORM_WINDOWS)
    (void) name;
    return MonitorBackend::createWsaPoll();
#else
    (void) name;
    return MonitorBackend::createDefault();
#endif
}

void forEachBackend(const std::function<void(Monitor&)>& body) {
#if defined(TASKPP_PLATFORM_WINDOWS) && !defined(TASKPP_PLATFORM_POSIX)
    Monitor monitor(MonitorBackend::createWsaPoll());
    body(monitor);
#else
    for (const char* name : { "epoll", "poll" }) {
        Monitor monitor(makeBackend(name));
        body(monitor);
    }
#endif
}

} // namespace

TEST(wait_single_fd) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadPooledWorker>(2);
        Pipe p;

        std::thread writer([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            p.write();
        });

        const int e = w->sync_wait(waitReadable(&monitor, p.r, { }));
        writer.join();
        CHECK(e & FD_READ);
    });
}

TEST(already_ready_fd) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe p;
        p.write();
        CHECK(w->sync_wait(waitReadable(&monitor, p.r, { })) & FD_READ);
    });
}

TEST(when_any) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe a, b, c;
        b.write();
        c.write();

        auto ready = w->sync_wait(waitAny(&monitor, { a.r, b.r, c.r }));
        CHECK(!ready.empty());
        for (auto& info : ready) {
            CHECK(info.fd == b.r || info.fd == c.r);
            CHECK(info.e & FD_READ);
        }
    });
}

TEST(hangup_is_reported) {
#if defined(TASKPP_PLATFORM_WINDOWS) && !defined(TASKPP_PLATFORM_POSIX)
    // TCP hangup reporting differs; writer shutdown still yields readability.
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe p;
        p.closeWriter();
        ::shutdown(static_cast<SOCKET>(p.r), SD_BOTH);
        CHECK(w->sync_wait(waitReadable(&monitor, p.r, { })) & (FD_READ | FD_HANGUP));
    });
#else
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe p;
        ::close(static_cast<int>(p.w));
        p.w = -1;
        CHECK(w->sync_wait(waitReadable(&monitor, p.r, { })) & FD_HANGUP);
    });
#endif
}

TEST(wait_cancellation) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe p;

        CancellerSource cs;
        cs.cancelAfter(TimeSpan::fromMilliseconds(20));
        CHECK_THROWS(OperationCanceled, w->sync_wait(waitReadable(&monitor, p.r, cs.canceller)));

        // the fd is usable again afterwards.
        p.write();
        CHECK(w->sync_wait(waitReadable(&monitor, p.r, { })) & FD_READ);
    });
}

TEST(cancel_fd) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe p;

        std::thread canceller([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            monitor.cancel(p.r);
        });

        CHECK_THROWS(OperationCanceled, w->sync_wait(waitReadable(&monitor, p.r, { })));
        canceller.join();
    });
}

TEST(streaming_and_affinity) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadPooledWorker>(3);
        Pipe p;

        std::thread writer([&] {
            for (int i = 0; i < 2000; ++i) {
                p.write();
                if (i % 100 == 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        });

        CHECK(w->sync_wait(echoLoop(&monitor, &p, 2000)) == 2000);
        writer.join();

        Pipe q;
        q.write();
        CHECK(w->sync_wait(resumesOnSameWorker(&monitor, q.r)));
    });
}

TEST(many_concurrent_waiters_on_one_fd) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadPooledWorker>(4);
        Pipe p;
        std::atomic<int> woke { 0 };

        for (int i = 0; i < 50; ++i) {
            w->push([](Monitor* m, IoFd fd, std::atomic<int>* woke) -> Task<void> {
                co_await m->watch(fd, FD_READ);
                woke->fetch_add(1);
            }(&monitor, p.r, &woke));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        p.write();
        w->wait();
        CHECK(woke.load() == 50);
    });
}

TEST(invalid_arguments) {
    CHECK_THROWS(std::invalid_argument, Monitor::wait(-1, FD_READ));
    CHECK_THROWS(std::invalid_argument, Monitor::wait(0, 0));
    CHECK_THROWS(std::invalid_argument, Monitor::whenAny(std::vector<IoEventInfo> { }));
}

TEST(default_monitor_static_api) {
    auto w = Worker::defaultWorker();
    Pipe p;
    p.write();
    CHECK(Monitor::defaultMonitor().backendName() != nullptr);
    const int e = w->sync_wait([](IoFd fd) -> Task<int> {
        co_return co_await Monitor::wait(fd, FD_READ | FD_WRITE);
    }(p.r));
    CHECK(e & FD_READ);
}

TEST_MAIN()
