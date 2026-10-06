// SocketAddress implementation: numeric factories, resolution, printing.
// Only this file interprets the opaque bytes (as sockaddr_*).
#include <taskpp/socket/SocketAddress.hpp>

#include <cstring>
#include <stdexcept>

#if defined(TASKPP_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "Native.hpp"

namespace taskpp {
namespace {

static_assert(sizeof(sockaddr_storage) <= 128, "SocketAddress storage too small.");

const sockaddr_in* asV4(const SocketAddress& addr) noexcept {
    return static_cast<const sockaddr_in*>(addr.data());
}

sockaddr_in* asV4(SocketAddress& addr) noexcept {
    return static_cast<sockaddr_in*>(addr.data());
}

const sockaddr_in6* asV6(const SocketAddress& addr) noexcept {
    return static_cast<const sockaddr_in6*>(addr.data());
}

sockaddr_in6* asV6(SocketAddress& addr) noexcept {
    return static_cast<sockaddr_in6*>(addr.data());
}

int rawFamily(const SocketAddress& addr) noexcept {
    return static_cast<const sockaddr*>(addr.data())->sa_family;
}

} // namespace

SocketAddress SocketAddress::fromIp(const std::string& ip, std::uint16_t port) {
    detail::ensureWsa();
    SocketAddress addr;
    if (::inet_pton(AF_INET, ip.c_str(), &asV4(addr)->sin_addr) == 1) {
        asV4(addr)->sin_family = AF_INET;
        asV4(addr)->sin_port = htons(port);
        addr.setLength(sizeof(sockaddr_in));
        return addr;
    }
    if (::inet_pton(AF_INET6, ip.c_str(), &asV6(addr)->sin6_addr) == 1) {
        asV6(addr)->sin6_family = AF_INET6;
        asV6(addr)->sin6_port = htons(port);
        addr.setLength(sizeof(sockaddr_in6));
        return addr;
    }
    throw std::invalid_argument("not a numeric IP address: " + ip);
}

SocketAddress SocketAddress::fromRaw(const void* bytes, std::size_t len) {
    if (!bytes) {
        throw std::invalid_argument("fromRaw: null bytes.");
    }
    const int family = static_cast<const sockaddr*>(bytes)->sa_family;
    const std::size_t want = family == AF_INET ? sizeof(sockaddr_in)
        : family == AF_INET6 ? sizeof(sockaddr_in6) : 0;
    if (want == 0 || len < want || want > sizeof(sockaddr_storage)) {
        throw std::invalid_argument("fromRaw: unknown family or bad length.");
    }
    SocketAddress addr;
    std::memcpy(addr.data(), bytes, want);
    addr.setLength(want);
    return addr;
}

void SocketAddress::setPort(std::uint16_t port) {
    switch (family()) {
    case AddressFamily::IPv4:
        asV4(*this)->sin_port = htons(port);
        break;
    case AddressFamily::IPv6:
        asV6(*this)->sin6_port = htons(port);
        break;
    default:
        throw std::logic_error("SocketAddress::setPort() on an empty address.");
    }
}

SocketAddress SocketAddress::loopback(std::uint16_t port, bool v6) {
    SocketAddress addr;
    if (v6) {
        asV6(addr)->sin6_family = AF_INET6;
        asV6(addr)->sin6_addr = in6addr_loopback;
        asV6(addr)->sin6_port = htons(port);
        addr.setLength(sizeof(sockaddr_in6));
    }
    else {
        asV4(addr)->sin_family = AF_INET;
        asV4(addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        asV4(addr)->sin_port = htons(port);
        addr.setLength(sizeof(sockaddr_in));
    }
    return addr;
}

SocketAddress SocketAddress::wildcard(std::uint16_t port, bool v6) {
    SocketAddress addr;
    if (v6) {
        asV6(addr)->sin6_family = AF_INET6;
        asV6(addr)->sin6_addr = in6addr_any;
        asV6(addr)->sin6_port = htons(port);
        addr.setLength(sizeof(sockaddr_in6));
    }
    else {
        asV4(addr)->sin_family = AF_INET;
        asV4(addr)->sin_addr.s_addr = htonl(INADDR_ANY);
        asV4(addr)->sin_port = htons(port);
        addr.setLength(sizeof(sockaddr_in));
    }
    return addr;
}

AddressFamily SocketAddress::family() const noexcept {
    if (len_ == 0) {
        return AddressFamily::Unspecified;
    }
    switch (rawFamily(*this)) {
    case AF_INET:
        return AddressFamily::IPv4;
    case AF_INET6:
        return AddressFamily::IPv6;
    default:
        return AddressFamily::Unspecified;
    }
}

void SocketAddress::prepareReceive() noexcept {
    len_ = sizeof(storage_);
}

void SocketAddress::setLength(std::size_t len) noexcept {
    len_ = len <= sizeof(storage_) ? len : sizeof(storage_);
}

std::uint16_t SocketAddress::port() const {
    switch (family()) {
    case AddressFamily::IPv4:
        return ntohs(asV4(*this)->sin_port);
    case AddressFamily::IPv6:
        return ntohs(asV6(*this)->sin6_port);
    default:
        throw std::logic_error("SocketAddress::port() on an empty address.");
    }
}

std::string SocketAddress::host() const {
    if (len_ == 0) {
        throw std::logic_error("SocketAddress::host() on an empty address.");
    }
    detail::ensureWsa();
    char buffer[NI_MAXHOST] = { };
    if (::getnameinfo(static_cast<const sockaddr*>(data()), static_cast<socklen_t>(size()),
            buffer, sizeof(buffer), nullptr, 0, NI_NUMERICHOST) != 0) {
        throw std::runtime_error("getnameinfo: cannot format address.");
    }
    return std::string(buffer);
}

std::string SocketAddress::toString() const {
    const std::string h = host();
    if (family() == AddressFamily::IPv6) {
        return "[" + h + "]:" + std::to_string(port());
    }
    return h + ":" + std::to_string(port());
}

bool operator==(const SocketAddress& a, const SocketAddress& b) noexcept {
    return a.len_ == b.len_ && std::memcmp(a.data(), b.data(), a.len_) == 0;
}

} // namespace taskpp
