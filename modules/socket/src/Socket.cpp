// Socket module implementation: one coroutine socket over Monitor.
#include <taskpp/socket/Socket.hpp>

#include <cstring>
#include <exception>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>

#if defined(TASKPP_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/tcp.h>
#endif

#include "Native.hpp"

namespace taskpp {
namespace {

#if defined(TASKPP_PLATFORM_WINDOWS)
using NativeT = SOCKET;
constexpr NativeT kInvalidNative = INVALID_SOCKET;

int lastErrorCode() noexcept { return ::WSAGetLastError(); }

bool isWouldBlock(int code) noexcept { return code == WSAEWOULDBLOCK; }
bool isIntr(int code) noexcept { return code == WSAEINTR; }

// A non-blocking connect that is still in flight.
bool isInProgress(int code) noexcept {
    return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS || code == WSAEALREADY;
}

// Transient accept failures: the peer vanished before accept().
bool isAcceptRetry(int code) noexcept { return code == WSAECONNRESET; }

NativeT toNative(IoFd fd) noexcept { return static_cast<NativeT>(fd); }
IoFd fromNative(NativeT s) noexcept { return static_cast<IoFd>(s); }

void closeNative(IoFd fd) noexcept {
    ::closesocket(toNative(fd));
}

constexpr int sendFlags() noexcept { return 0; }

const sockaddr* sockAddr(const SocketAddress& addr) noexcept {
    return static_cast<const sockaddr*>(addr.data());
}

sockaddr* sockAddr(SocketAddress& addr) noexcept {
    return static_cast<sockaddr*>(addr.data());
}

int addrLen(const SocketAddress& addr) noexcept {
    return static_cast<int>(addr.size());
}

int nativeFamily(const SocketAddress& addr) noexcept {
    switch (addr.family()) {
    case AddressFamily::IPv4:
        return AF_INET;
    case AddressFamily::IPv6:
        return AF_INET6;
    default:
        return AF_UNSPEC;
    }
}

#else // POSIX

using NativeT = int;
constexpr NativeT kInvalidNative = -1;

int lastErrorCode() noexcept { return errno; }

bool isWouldBlock(int code) noexcept {
    return code == EAGAIN || code == EWOULDBLOCK;
}

bool isIntr(int code) noexcept { return code == EINTR; }

bool isInProgress(int code) noexcept {
    return code == EINPROGRESS || code == EALREADY
#if EAGAIN != EINPROGRESS
        || code == EAGAIN
#endif
#if EWOULDBLOCK != EINPROGRESS && EWOULDBLOCK != EAGAIN
        || code == EWOULDBLOCK
#endif
        ;
}

bool isAcceptRetry(int code) noexcept {
    return code == ECONNABORTED || code == EPROTO;
}

NativeT toNative(IoFd fd) noexcept { return static_cast<NativeT>(fd); }
IoFd fromNative(NativeT s) noexcept { return static_cast<IoFd>(s); }

void closeNative(IoFd fd) noexcept {
    ::close(toNative(fd));
}

constexpr int sendFlags() noexcept {
#if defined(MSG_NOSIGNAL)
    return MSG_NOSIGNAL; // no SIGPIPE on Linux when the peer went away.
#else
    return 0;
#endif
}

const sockaddr* sockAddr(const SocketAddress& addr) noexcept {
    return static_cast<const sockaddr*>(addr.data());
}

sockaddr* sockAddr(SocketAddress& addr) noexcept {
    return static_cast<sockaddr*>(addr.data());
}

socklen_t addrLen(const SocketAddress& addr) noexcept {
    return static_cast<socklen_t>(addr.size());
}

int nativeFamily(const SocketAddress& addr) noexcept {
    switch (addr.family()) {
    case AddressFamily::IPv4:
        return AF_INET;
    case AddressFamily::IPv6:
        return AF_INET6;
    default:
        return AF_UNSPEC;
    }
}

#endif

[[noreturn]] void throwLastError(const char* what) {
    throw std::system_error(lastErrorCode(), std::system_category(), what);
}

void setNonBlocking(IoFd fd) {
#if defined(TASKPP_PLATFORM_WINDOWS)
    u_long on = 1;
    if (::ioctlsocket(toNative(fd), FIONBIO, &on) == SOCKET_ERROR) {
        throwLastError("ioctlsocket(FIONBIO)");
    }
#else
    const int flags = ::fcntl(toNative(fd), F_GETFL, 0);
    if (flags < 0) {
        throwLastError("fcntl(F_GETFL)");
    }
    if (::fcntl(toNative(fd), F_SETFL, flags | O_NONBLOCK) < 0) {
        throwLastError("fcntl(O_NONBLOCK)");
    }
#endif
}

int socketTypeOption(SocketType type) noexcept {
    return type == SocketType::Tcp ? SOCK_STREAM : SOCK_DGRAM;
}

IoFd createNonblocking(const SocketAddress& addr, SocketType type) {
#if defined(TASKPP_PLATFORM_WINDOWS)
    detail::ensureWsa();
#endif
    NativeT s = ::socket(nativeFamily(addr), socketTypeOption(type), 0);
    if (s == kInvalidNative) {
        throwLastError("socket");
    }
    IoFd fd = fromNative(s);
    try {
        setNonBlocking(fd);
    }
    catch (...) {
        closeNative(fd);
        throw;
    }
    return fd;
}

void setReuseAddressOn(IoFd fd) {
    int reuse = 1;
#if defined(TASKPP_PLATFORM_WINDOWS)
    ::setsockopt(toNative(fd), SOL_SOCKET, SO_REUSEADDR,
        reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#else
    ::setsockopt(toNative(fd), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
}

// SO_ERROR of a non-blocking connect: 0 = established.
int socketError(IoFd fd) noexcept {
    int err = 0;
    socklen_t len = sizeof(err);
#if defined(TASKPP_PLATFORM_WINDOWS)
    ::getsockopt(toNative(fd), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
#else
    ::getsockopt(toNative(fd), SOL_SOCKET, SO_ERROR, &err, &len);
#endif
    return err;
}

} // namespace

// ------------------------------------------------------------------ Socket

Socket::Socket(Socket&& other) noexcept : fd_(std::exchange(other.fd_, invalid())) { }

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = std::exchange(other.fd_, invalid());
    }
    return *this;
}

Socket::~Socket() {
    close();
}

void Socket::close() noexcept {
    const IoFd fd = std::exchange(fd_, invalid());
    if (fd == invalid()) {
        return;
    }
    // Wake parked waits first so they throw OperationCanceled instead of
    // touching a recycled descriptor number afterwards.
    try {
        Monitor::defaultMonitor().cancel(fd);
    }
    catch (...) {
    }
    closeNative(fd);
}

Task<Socket> Socket::connectOne(const SocketAddress& addr, Canceller canceller, SocketType type) {
    Socket s(createNonblocking(addr, type));

    const int rc = ::connect(toNative(s.fd()), sockAddr(addr), addrLen(addr));
    if (rc == 0) {
        co_return std::move(s);
    }
    if (!isInProgress(lastErrorCode())) {
        throwLastError("connect");
    }

    co_await Monitor::wait(s.fd(), IoWrite, canceller);

    if (const int err = socketError(s.fd()); err != 0) {
        throw std::system_error(err, std::system_category(), "connect");
    }
    co_return std::move(s);
}

Task<Socket> Socket::connect(std::string host, std::uint16_t port,
    Canceller canceller, SocketType type) {
    auto addresses = co_await Dns::resolve(std::move(host), port, type, canceller);

    std::exception_ptr last;
    for (const auto& addr : addresses) {
        try {
            co_return co_await connectOne(addr, canceller, type);
        }
        catch (const OperationCanceled&) {
            throw; // user abort: never fall through to the next address.
        }
        catch (...) {
            last = std::current_exception();
        }
    }

    if (last) {
        std::rethrow_exception(last);
    }
    throw std::runtime_error("connect: no addresses resolved.");
}

Task<Socket> Socket::connect(const SocketAddress& addr, Canceller canceller, SocketType type) {
    canceller.throwIfCanceled();
    if (addr.empty()) {
        throw std::invalid_argument("connect: empty address.");
    }
    co_return co_await connectOne(addr, std::move(canceller), type);
}

Socket Socket::bind(const std::string& host, std::uint16_t port,
    SocketType type, int backlog) {
    auto addresses = Dns::resolveSync(host, port, type);

    std::exception_ptr last;
    for (const auto& addr : addresses) {
        try {
            return bind(addr, type, backlog);
        }
        catch (...) {
            last = std::current_exception();
        }
    }

    if (last) {
        std::rethrow_exception(last);
    }
    throw std::runtime_error("bind: no addresses resolved.");
}

Socket Socket::bind(const SocketAddress& addr, SocketType type, int backlog) {
    if (addr.empty()) {
        throw std::invalid_argument("bind: empty address.");
    }
#if defined(TASKPP_PLATFORM_WINDOWS)
    detail::ensureWsa();
#endif
    Socket s(createNonblocking(addr, type));
    setReuseAddressOn(s.fd());

    if (::bind(toNative(s.fd()), sockAddr(addr), addrLen(addr)) != 0) {
        throwLastError("bind");
    }
    if (type == SocketType::Tcp && ::listen(toNative(s.fd()), backlog) != 0) {
        throwLastError("listen");
    }
    return s;
}

Task<Socket> Socket::accept(Canceller canceller) {
    canceller.throwIfCanceled();
    while (true) {
        const NativeT raw = ::accept(toNative(fd_), nullptr, nullptr);
        if (raw != kInvalidNative) {
            const IoFd fd = fromNative(raw);
            setNonBlocking(fd);
            co_return Socket(fd);
        }
        const int code = lastErrorCode();
        if (isWouldBlock(code)) {
            co_await Monitor::wait(fd_, IoRead, canceller);
        }
        else if (isIntr(code) || isAcceptRetry(code)) {
            continue; // transient: interrupted, or the peer vanished first.
        }
        else {
            throw std::system_error(code, std::system_category(), "accept");
        }
    }
}

Task<std::size_t> Socket::sendSome(std::span<const char> data, Canceller canceller) {
    canceller.throwIfCanceled();
    if (data.empty()) {
        co_return 0;
    }
    std::size_t total = data.size();
    if (total > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        total = static_cast<std::size_t>((std::numeric_limits<int>::max)());
    }
    while (true) {
#if defined(TASKPP_PLATFORM_WINDOWS)
        const int n = ::send(toNative(fd_), data.data(), static_cast<int>(total), sendFlags());
#else
        const auto n = ::send(toNative(fd_), data.data(), total, sendFlags());
#endif
        if (n > 0) {
            co_return static_cast<std::size_t>(n);
        }
        const int code = lastErrorCode();
        if (isWouldBlock(code)) {
            co_await Monitor::wait(fd_, IoWrite, canceller);
            continue;
        }
        if (isIntr(code)) {
            continue;
        }
        if (n == 0) {
            throw SocketClosed("send: the peer closed the connection.");
        }
        throw std::system_error(code, std::system_category(), "send");
    }
}

Task<void> Socket::sendAll(std::span<const char> data, Canceller canceller) {
    std::size_t done = 0;
    while (done < data.size()) {
        done += co_await sendSome(data.subspan(done), canceller);
    }
    co_return;
}

Task<std::size_t> Socket::recvSome(std::span<char> buffer, Canceller canceller) {
    canceller.throwIfCanceled();
    if (buffer.empty()) {
        co_return 0;
    }
    std::size_t total = buffer.size();
    if (total > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        total = static_cast<std::size_t>((std::numeric_limits<int>::max)());
    }
    while (true) {
#if defined(TASKPP_PLATFORM_WINDOWS)
        const int n = ::recv(toNative(fd_), buffer.data(), static_cast<int>(total), 0);
#else
        const auto n = ::recv(toNative(fd_), buffer.data(), total, 0);
#endif
        if (n > 0) {
            co_return static_cast<std::size_t>(n);
        }
        if (n == 0) {
            co_return 0; // orderly shutdown.
        }
        const int code = lastErrorCode();
        if (isWouldBlock(code)) {
            co_await Monitor::wait(fd_, IoRead, canceller);
            continue;
        }
        if (isIntr(code)) {
            continue;
        }
        throw std::system_error(code, std::system_category(), "recv");
    }
}

Task<void> Socket::recvExact(std::span<char> buffer, Canceller canceller) {
    std::size_t done = 0;
    while (done < buffer.size()) {
        const std::size_t n = co_await recvSome(buffer.subspan(done), canceller);
        if (n == 0) {
            throw SocketClosed("recv: the peer closed the connection.");
        }
        done += n;
    }
    co_return;
}

Task<std::size_t> Socket::sendTo(std::span<const char> data, const std::string& host,
    std::uint16_t port, Canceller canceller) {
    auto addresses = co_await Dns::resolve(host, port, SocketType::Udp, canceller);

    std::exception_ptr last;
    for (const auto& addr : addresses) {
        try {
            co_return co_await sendTo(data, addr, canceller);
        }
        catch (const OperationCanceled&) {
            throw;
        }
        catch (...) {
            last = std::current_exception();
        }
    }

    if (last) {
        std::rethrow_exception(last);
    }
    throw std::runtime_error("sendTo: no addresses resolved.");
}

Task<std::size_t> Socket::sendTo(std::span<const char> data, const SocketAddress& addr,
    Canceller canceller) {
    canceller.throwIfCanceled();
    if (addr.empty()) {
        throw std::invalid_argument("sendTo: empty address.");
    }
    if (data.empty()) {
        co_return 0;
    }
    std::size_t total = data.size();
    if (total > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        total = static_cast<std::size_t>((std::numeric_limits<int>::max)());
    }
    while (true) {
#if defined(TASKPP_PLATFORM_WINDOWS)
        const int n = ::sendto(toNative(fd_), data.data(), static_cast<int>(total), sendFlags(),
            sockAddr(addr), addrLen(addr));
#else
        const auto n = ::sendto(toNative(fd_), data.data(), total, sendFlags(),
            sockAddr(addr), addrLen(addr));
#endif
        if (n >= 0) {
            co_return static_cast<std::size_t>(n);
        }
        const int code = lastErrorCode();
        if (isWouldBlock(code)) {
            co_await Monitor::wait(fd_, IoWrite, canceller);
            continue;
        }
        if (isIntr(code)) {
            continue;
        }
        throw std::system_error(code, std::system_category(), "sendto");
    }
}

Task<std::pair<std::size_t, Peer>> Socket::recvFrom(std::span<char> buffer, Canceller canceller) {
    canceller.throwIfCanceled();
    if (buffer.empty()) {
        co_return std::pair<std::size_t, Peer> { 0, { } };
    }
    std::size_t total = buffer.size();
    if (total > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        total = static_cast<std::size_t>((std::numeric_limits<int>::max)());
    }
    while (true) {
        SocketAddress from;
        from.prepareReceive();
#if defined(TASKPP_PLATFORM_WINDOWS)
        int fromLen = static_cast<int>(from.size());
        const int n = ::recvfrom(toNative(fd_), buffer.data(), static_cast<int>(total), 0,
            sockAddr(from), &fromLen);
        from.setLength(static_cast<std::size_t>(fromLen));
#else
        socklen_t fromLen = static_cast<socklen_t>(from.size());
        const auto n = ::recvfrom(toNative(fd_), buffer.data(), total, 0,
            sockAddr(from), &fromLen);
        from.setLength(static_cast<std::size_t>(fromLen));
#endif
        if (n >= 0) {
            Peer sender { from.host(), from.port() };
            co_return std::pair<std::size_t, Peer> { static_cast<std::size_t>(n), std::move(sender) };
        }
        const int code = lastErrorCode();
        if (isWouldBlock(code)) {
            co_await Monitor::wait(fd_, IoRead, canceller);
            continue;
        }
        if (isIntr(code)) {
            continue;
        }
        throw std::system_error(code, std::system_category(), "recvfrom");
    }
}

void Socket::setNoDelay(bool enable) {
    int flag = enable ? 1 : 0;
#if defined(TASKPP_PLATFORM_WINDOWS)
    if (::setsockopt(toNative(fd_), IPPROTO_TCP, TCP_NODELAY,
            reinterpret_cast<const char*>(&flag), sizeof(flag)) == SOCKET_ERROR) {
        throwLastError("setsockopt(TCP_NODELAY)");
    }
#else
    if (::setsockopt(toNative(fd_), IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) != 0) {
        throwLastError("setsockopt(TCP_NODELAY)");
    }
#endif
}

void Socket::setReuseAddress(bool enable) {
    int flag = enable ? 1 : 0;
#if defined(TASKPP_PLATFORM_WINDOWS)
    if (::setsockopt(toNative(fd_), SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&flag), sizeof(flag)) == SOCKET_ERROR) {
        throwLastError("setsockopt(SO_REUSEADDR)");
    }
#else
    if (::setsockopt(toNative(fd_), SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0) {
        throwLastError("setsockopt(SO_REUSEADDR)");
    }
#endif
}

void Socket::shutdown(ShutdownHow how) noexcept {
    if (fd_ == invalid()) {
        return;
    }
#if defined(TASKPP_PLATFORM_WINDOWS)
    const int h = how == ShutdownHow::Read ? SD_RECEIVE : how == ShutdownHow::Write ? SD_SEND : SD_BOTH;
#else
    const int h = how == ShutdownHow::Read ? SHUT_RD : how == ShutdownHow::Write ? SHUT_WR : SHUT_RDWR;
#endif
    (void) ::shutdown(toNative(fd_), h);
}

std::uint16_t Socket::localPort() const {
    if (fd_ == invalid()) {
        throw std::logic_error("localPort() on an empty socket.");
    }
    SocketAddress addr;
    addr.prepareReceive();
#if defined(TASKPP_PLATFORM_WINDOWS)
    int len = static_cast<int>(addr.size());
    if (::getsockname(toNative(fd_), sockAddr(addr), &len) != 0) {
        throwLastError("getsockname");
    }
    addr.setLength(static_cast<std::size_t>(len));
#else
    socklen_t len = static_cast<socklen_t>(addr.size());
    if (::getsockname(toNative(fd_), sockAddr(addr), &len) != 0) {
        throwLastError("getsockname");
    }
    addr.setLength(static_cast<std::size_t>(len));
#endif
    return addr.port();
}

} // namespace taskpp
