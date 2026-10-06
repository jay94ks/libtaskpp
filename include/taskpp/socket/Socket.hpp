#pragma once
// A single coroutine based socket: TCP and UDP are creation options, not
// classes. `Socket` wraps nothing but the native handle. All names live in
// `taskpp`.
//
// A socket is non-blocking internally: every member suspends on the worker it
// was called on (worker affinity) and never blocks a worker thread, except for
// name resolution, which runs the blocking lookup inline (`Dns`; numeric
// literals resolve without any lookup). There is
// intentionally no timeout parameter: race with `withTimeout` or pass a
// `Canceller` (`CancellerSource::cancelAfter`).
//
// Buffers passed as `std::span` must stay alive until the operation completes.
// Close semantics: `close()` first aborts parked waits (`OperationCanceled`)
// and then releases the native handle. Stop I/O via a `Canceller` before
// closing; an operation already past its wait may still observe EBADF.
#include <taskpp/Config.hpp>
#include <taskpp/Exceptions.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Monitor.hpp>
#include <taskpp/core/Task.hpp>
#include <taskpp/socket/Dns.hpp>
#include <taskpp/socket/SocketAddress.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

namespace taskpp {

/** Which directions `Socket::shutdown` closes. */
enum class ShutdownHow {
    Read,
    Write,
    Both,
};

/** Sender of a received datagram. */
struct Peer {
    std::string host;
    std::uint16_t port = 0;
};

/**
 * A move-only, RAII socket. One class for both transports:
 *
 *     // TCP server + client.
 *     Socket listener = Socket::bind("127.0.0.1", 0);  // port 0 = ephemeral
 *     Socket conn = co_await listener.accept(ct);
 *     Socket s = co_await Socket::connect("127.0.0.1", listener.localPort(), ct);
 *     co_await s.sendAll(std::span(data), ct);
 *     co_await s.recvExact(std::span(buffer), ct);
 *
 *     // UDP: bind both ends, then sendTo / recvFrom (or connect() for a
 *     // connected datagram socket and use send/recv on it).
 *     Socket a = Socket::bind("127.0.0.1", 0, SocketType::Udp);
 *     co_await a.sendTo(data, "127.0.0.1", b.localPort(), ct);
 *     auto [n, from] = co_await b.recvFrom(buffer, ct);
 *
 * `SocketAddress` overloads skip resolution for already-resolved peers.
 */
class Socket {
public:
    Socket() noexcept = default;

    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    ~Socket();

    /**
     * Connects to `host:port` (resolution via `Dns`, multi-address fallback).
     * TCP performs the stream handshake; UDP creates a connected datagram
     * socket (default remote peer: `send`/`recv` usable).
     */
    static Task<Socket> connect(std::string host, std::uint16_t port,
        Canceller canceller = { }, SocketType type = SocketType::Tcp);
    static Task<Socket> connect(const SocketAddress& addr,
        Canceller canceller = { }, SocketType type = SocketType::Tcp);

    /**
     * Binds `host:port` (port 0 = ephemeral, read back with `localPort()`).
     * TCP additionally starts listening (`backlog`); UDP only binds.
     */
    static Socket bind(const std::string& host, std::uint16_t port,
        SocketType type = SocketType::Tcp, int backlog = 128);
    static Socket bind(const SocketAddress& addr,
        SocketType type = SocketType::Tcp, int backlog = 128);

    /** Accepts the next pending connection (listening sockets; many acceptors OK). */
    Task<Socket> accept(Canceller canceller = { });

    /** Sends up to `data.size()` bytes; returns what was sent. */
    Task<std::size_t> sendSome(std::span<const char> data, Canceller canceller = { });

    /** Sends everything (no-op for empty spans). */
    Task<void> sendAll(std::span<const char> data, Canceller canceller = { });

    /**
     * Receives up to `buffer.size()` bytes; returns 0 on orderly peer shutdown
     * (and throws nothing). Empty buffers return 0 immediately.
     */
    Task<std::size_t> recvSome(std::span<char> buffer, Canceller canceller = { });

    /** Receives exactly `buffer.size()` bytes; throws `SocketClosed` on early EOF. */
    Task<void> recvExact(std::span<char> buffer, Canceller canceller = { });

    /** Sends one datagram (datagram sockets). */
    Task<std::size_t> sendTo(std::span<const char> data, const std::string& host,
        std::uint16_t port, Canceller canceller = { });
    Task<std::size_t> sendTo(std::span<const char> data, const SocketAddress& addr,
        Canceller canceller = { });

    /** Receives one datagram: `{ bytes, sender }` (empty buffers return `{0, {}}`). */
    Task<std::pair<std::size_t, Peer>> recvFrom(std::span<char> buffer, Canceller canceller = { });

    void setNoDelay(bool enable);
    void setReuseAddress(bool enable);

    /** Best-effort shutdown of one or both directions; never throws. */
    void shutdown(ShutdownHow how) noexcept;

    /** Aborts parked waits and releases the handle. Idempotent. */
    void close() noexcept;

    bool valid() const noexcept { return fd_ >= 0; }
    explicit operator bool() const noexcept { return valid(); }

    /** Native descriptor for `Monitor` interop (POSIX fd / Windows SOCKET). */
    IoFd fd() const noexcept { return fd_; }

    /** Local port this socket is bound to. */
    std::uint16_t localPort() const;

    /** Releases ownership of the native handle (caller must close it). */
    IoFd release() noexcept { return std::exchange(fd_, invalid()); }

    static constexpr IoFd invalid() noexcept { return static_cast<IoFd>(-1); }

private:
    explicit Socket(IoFd fd) noexcept : fd_(fd) { }

    static Task<Socket> connectOne(const SocketAddress& addr, Canceller canceller, SocketType type);

    IoFd fd_ = invalid();
};

} // namespace taskpp
