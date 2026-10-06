// Dns implementation: async resolution over c-ares, driven by Monitor.
//
// The single place that resolves names. Numeric literals resolve inline;
// hostnames go through c-ares with zero dedicated threads: socket readiness
// comes from Monitor::whenAny, retransmit deadlines from TimerService, worker
// affinity from the Completion/ResumeTarget machinery underneath.
#include <taskpp/socket/Dns.hpp>

#include <taskpp/core/Monitor.hpp>
#include <taskpp/core/Timer.hpp>

#include <ares.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#if defined(TASKPP_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#endif

#include "Native.hpp"

namespace taskpp {
namespace {

void ensureAres() {
    // Intentionally never cleaned up: lookups may be in flight during static
    // destruction, like the other process-wide singletons.
    static bool ready = []() {
        if (::ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
            throw std::runtime_error("ares_library_init failed.");
        }
        return true;
    }();
    (void) ready;
}

struct Query {
    bool done = false;
    int status = ARES_SUCCESS;
    ares_addrinfo* info = nullptr; // owned; freed after conversion.
    std::map<IoFd, int> interests; // ares socket -> IoRead|IoWrite.
};

void onSockState(void* data, ares_socket_t fd, int readable, int writable) {
    auto* query = static_cast<Query*>(data);
    const IoFd key = static_cast<IoFd>(fd);
    if (!readable && !writable) {
        query->interests.erase(key);
    }
    else {
        query->interests[key] = (readable ? IoRead : 0) | (writable ? IoWrite : 0);
    }
}

void onAddrInfo(void* arg, int status, int /*timeouts*/, ares_addrinfo* result) {
    auto* query = static_cast<Query*>(arg);
    query->done = true;
    query->status = status;
    query->info = result; // ownership passes to us; freed after conversion.
}

struct ChannelGuard {
    ares_channel_t* channel = nullptr;
    ~ChannelGuard() {
        if (channel) {
            ::ares_destroy(channel);
        }
    }
};

TimeSpan toTimeSpan(const timeval& tv) {
    const long long micros = static_cast<long long>(tv.tv_sec) * 1000000LL + tv.tv_usec;
    return TimeSpan::fromMicroseconds(micros);
}

} // namespace

std::vector<SocketAddress> Dns::resolveSync(const std::string& host,
    std::uint16_t port, SocketType type) {
    // Numeric literals never touch the network.
    if (!host.empty()) {
        try {
            return std::vector<SocketAddress> { SocketAddress::fromIp(host, port) };
        }
        catch (const std::invalid_argument&) {
            // A hostname: fall through to the system resolver below.
        }
    }

    detail::ensureWsa();

    addrinfo hints { };
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type == SocketType::Tcp ? SOCK_STREAM : SOCK_DGRAM;
    if (host.empty()) {
        hints.ai_flags = AI_PASSIVE;
    }

    const std::string service = std::to_string(port);
    const char* node = host.empty() ? nullptr : host.c_str();

    addrinfo* list = nullptr;
    const int rc = ::getaddrinfo(node, service.c_str(), &hints, &list);
    if (rc != 0) {
        throw std::runtime_error(std::string("getaddrinfo: ") + ::gai_strerror(rc));
    }

    std::vector<SocketAddress> out;
    for (const addrinfo* ai = list; ai != nullptr; ai = ai->ai_next) {
        SocketAddress addr;
        addr.prepareReceive();
        if (static_cast<std::size_t>(ai->ai_addrlen) > addr.size()) {
            continue;
        }
        std::memcpy(addr.data(), ai->ai_addr, static_cast<std::size_t>(ai->ai_addrlen));
        addr.setLength(static_cast<std::size_t>(ai->ai_addrlen));
        out.push_back(addr);
    }
    ::freeaddrinfo(list);

    if (out.empty()) {
        throw std::runtime_error("getaddrinfo: no addresses for " + host);
    }
    return out;
}

Task<std::vector<SocketAddress>> Dns::resolve(std::string host, std::uint16_t port,
    SocketType type, Canceller canceller) {
    canceller.throwIfCanceled();

    // Numeric literals resolve inline: no thread hop, no DNS traffic.
    if (!host.empty()) {
        try {
            co_return std::vector<SocketAddress> { SocketAddress::fromIp(host, port) };
        }
        catch (const std::invalid_argument&) {
            // A hostname: fall through to c-ares below.
        }
    }
    if (host.empty()) {
        co_return std::vector<SocketAddress> { SocketAddress::wildcard(port) };
    }

    detail::ensureWsa();
    ensureAres();

    ChannelGuard guard;
    Query query;
    {
        ares_options opts { };
        opts.sock_state_cb = onSockState;
        opts.sock_state_cb_data = &query;
        ares_channel_t* channel = nullptr;
        if (const int rc = ::ares_init_options(&channel, &opts, ARES_OPT_SOCK_STATE_CB);
            rc != ARES_SUCCESS) {
            throw std::runtime_error(std::string("ares_init: ") + ::ares_strerror(rc));
        }
        guard.channel = channel;
    }

    ares_addrinfo_hints hints { };
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type == SocketType::Tcp ? SOCK_STREAM : SOCK_DGRAM;
    const std::string service = std::to_string(port);
    ::ares_getaddrinfo(guard.channel, host.c_str(), service.c_str(), &hints, onAddrInfo, &query);

    // Drive c-ares: readiness from Monitor, deadlines from the timer, worker
    // affinity from the awaitables underneath. No thread is ever blocked here.
    while (!query.done) {
        timeval tv { };
        const timeval* deadline = ::ares_timeout(guard.channel, nullptr, &tv);
        const bool haveTimeout = deadline != nullptr
            && (deadline->tv_sec > 0 || (deadline->tv_sec == 0 && deadline->tv_usec > 0));
        const TimeSpan waitFor = haveTimeout ? toTimeSpan(*deadline) : TimeSpan::max();

        std::vector<IoEventInfo> interests;
        interests.reserve(query.interests.size());
        for (const auto& [fd, events] : query.interests) {
            interests.push_back({ fd, events });
        }

        CancellerSource timeoutSource;
        if (haveTimeout) {
            timeoutSource.cancelAfter(waitFor);
        }
        CancellerSource linked({ canceller, timeoutSource.canceller });
        try {
            if (!interests.empty()) {
                const auto ready = co_await Monitor::whenAny(std::move(interests), linked.canceller);
                std::vector<ares_fd_events_t> events;
                events.reserve(ready.size());
                for (const auto& r : ready) {
                    events.push_back({
                        static_cast<ares_socket_t>(r.fd),
                        static_cast<unsigned int>(((r.e & IoRead) ? ARES_FD_EVENT_READ : 0)
                            | ((r.e & IoWrite) ? ARES_FD_EVENT_WRITE : 0)),
                    });
                }
                ::ares_process_fds(guard.channel, events.data(), events.size(), ARES_PROCESS_FLAG_NONE);
            }
            else {
                if (!haveTimeout) {
                    // No sockets, no deadline, not done: never spin; fail loudly.
                    ::ares_cancel(guard.channel);
                    throw std::runtime_error("c-ares: stalled without sockets or timeout.");
                }
                co_await delay(waitFor, linked.canceller);
                ::ares_process_fds(guard.channel, nullptr, 0, ARES_PROCESS_FLAG_NONE);
            }
        }
        catch (const OperationCanceled&) {
            if (canceller.isTriggered()) {
                ::ares_cancel(guard.channel);
                throw;
            }
            // Our own retransmit deadline: pump timeouts, then continue.
            ::ares_process_fds(guard.channel, nullptr, 0, ARES_PROCESS_FLAG_NONE);
        }
    }

    if (query.status != ARES_SUCCESS) {
        if (query.info) {
            ::ares_freeaddrinfo(query.info);
        }
        throw std::runtime_error(std::string("c-ares: ") + ::ares_strerror(query.status));
    }

    std::vector<SocketAddress> out;
    for (auto* node = query.info ? query.info->nodes : nullptr; node != nullptr; node = node->ai_next) {
        try {
            SocketAddress addr = SocketAddress::fromRaw(node->ai_addr,
                static_cast<std::size_t>(node->ai_addrlen));
            addr.setPort(port);
            out.push_back(addr);
        }
        catch (...) {
            // Skip families we cannot represent.
        }
    }
    if (query.info) {
        ::ares_freeaddrinfo(query.info);
    }
    if (out.empty()) {
        throw std::runtime_error("c-ares: no addresses for " + host);
    }
    co_return out;
}

Task<std::vector<std::string>> Dns::lookup(std::string host, Canceller canceller) {
    auto addresses = co_await resolve(std::move(host), 0, SocketType::Tcp, std::move(canceller));

    std::vector<std::string> records;
    for (const auto& addr : addresses) {
        const std::string ip = addr.host();
        if (std::find(records.begin(), records.end(), ip) == records.end()) {
            records.push_back(ip);
        }
    }
    co_return records;
}

} // namespace taskpp
