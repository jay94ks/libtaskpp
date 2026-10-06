#pragma once
// A value-type internet address (IPv4/IPv6 + port). All names live in `taskpp`.
//
// The header is OS-clean: it includes no socket headers, so Windows consumers
// never see `<winsock2.h>` (no macro clashes, no include-order hazards). The
// address bytes are opaque storage; only the .cpp interprets them.
#include <taskpp/Config.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace taskpp {

/** Transport selected at creation time (an option, not stored state). */
enum class SocketType {
    Tcp,
    Udp,
};

/** Address family without touching OS headers. */
enum class AddressFamily {
    Unspecified,
    IPv4,
    IPv6,
};

/**
 * An internet socket address: family + numeric host + port.
 *
 *     auto addrs = SocketAddress::resolve("example.com", 80, SocketType::Tcp);
 *     SocketAddress self = SocketAddress::loopback(0);   // 127.0.0.1:0
 *     SocketAddress any = SocketAddress::wildcard(8080);  // 0.0.0.0:8080
 */
class SocketAddress {
public:
    SocketAddress() noexcept = default;

    SocketAddress(const SocketAddress&) = default;
    SocketAddress& operator=(const SocketAddress&) = default;

    /** Numeric loopback (`127.0.0.1` or `::1`); no resolution involved. */
    static SocketAddress loopback(std::uint16_t port, bool v6 = false);

    /** Numeric wildcard (`0.0.0.0` or `::`); no resolution involved. */
    static SocketAddress wildcard(std::uint16_t port, bool v6 = false);

    /**
     * Parses a numeric IP literal; throws `std::invalid_argument` for anything
     * else (hostnames go through `resolve` / `Dns`).
     */
    static SocketAddress fromIp(const std::string& ip, std::uint16_t port);

    /**
     * Wraps raw address bytes (e.g. from a resolver callback); throws
     * `std::invalid_argument` for unknown families or oversized input.
     */
    static SocketAddress fromRaw(const void* bytes, std::size_t len);

    /** Overwrites the port (host byte order). */
    void setPort(std::uint16_t port);

    AddressFamily family() const noexcept;

    bool empty() const noexcept { return len_ == 0; }

    /** Port in host byte order (throws `std::logic_error` when empty). */
    std::uint16_t port() const;

    /** Numeric host string (throws `std::logic_error` when empty). */
    std::string host() const;

    /** `"host:port"` (IPv6 hosts bracketed). */
    std::string toString() const;

    // --> raw bytes for syscalls (interpreted as `sockaddr` in the .cpp only).
    const void* data() const noexcept { return storage_; }
    void* data() noexcept { return storage_; }
    std::size_t size() const noexcept { return len_; }

    /**
     * Prepares this object as a writable slot for syscalls that fill in an
     * address (`accept`, `recvfrom`, `getsockname`): resets the length to the
     * storage capacity. Afterwards the syscall has set the actual length.
     */
    void prepareReceive() noexcept;
    void setLength(std::size_t len) noexcept;

    friend bool operator==(const SocketAddress& a, const SocketAddress& b) noexcept;

private:
    // Opaque bytes: large and aligned enough for any sockaddr (§ storage).
    alignas(std::max_align_t) unsigned char storage_[128] { };
    std::size_t len_ = 0;
};

} // namespace taskpp
