#pragma once
// Coroutine based DNS: record lookup with a uniform awaitable API.
// Resolution lives here and only here (`SocketAddress` is a pure value type).
// All names live in `taskpp`.
//
// Numeric literals (and the empty host) resolve inline with no suspension.
// Hostnames go through c-ares (static build from `third_party/c-ares`),
// driven by the Monitor reactor and the timer: no thread is ever blocked.
// There is intentionally no separate resolver thread pool.
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Task.hpp>
#include <taskpp/socket/SocketAddress.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace taskpp {

/**
 * DNS resolver: the single owner of name resolution.
 *
 *     // A/AAAA addresses for a name (empty host = wildcard, for binds).
 *     std::vector<SocketAddress> addrs =
 *         co_await Dns::resolve("example.com", 80, SocketType::Tcp, ct);
 *
 *     // Same, synchronously (for non-coroutine contexts like bind()).
 *     std::vector<SocketAddress> sync =
 *         Dns::resolveSync("example.com", 80, SocketType::Tcp);
 *
 *     // Numeric address strings only ("records" view, no ports).
 *     std::vector<std::string> ips = co_await Dns::lookup("example.com", ct);
 *
 * Cancellation throws `OperationCanceled`. Failures throw `std::runtime_error`
 * (`getaddrinfo` message). The awaiting coroutine always resumes on the worker
 * it suspended on (resolution itself never migrates it).
 */
class Dns {
public:
    Dns() = delete;

    static Task<std::vector<SocketAddress>> resolve(std::string host, std::uint16_t port,
        SocketType type = SocketType::Tcp, Canceller canceller = { });

    static std::vector<SocketAddress> resolveSync(const std::string& host,
        std::uint16_t port, SocketType type = SocketType::Tcp);

    static Task<std::vector<std::string>> lookup(std::string host, Canceller canceller = { });
};

} // namespace taskpp
