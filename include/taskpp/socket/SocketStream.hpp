#pragma once
// `Stream` over a connected `Socket`. Lives in the socket module because it
// binds the abstraction to sockets. All names live in `taskpp`.
#include <taskpp/core/Stream.hpp>
#include <taskpp/socket/Socket.hpp>

namespace taskpp {

/** `Stream` over a connected `Socket`. Takes ownership. */
class SocketStream : public Stream {
public:
    explicit SocketStream(Socket socket) noexcept;

    Task<void> write(std::span<const char> data, Canceller canceller = { }) override;
    Task<std::size_t> readSome(std::span<char> buffer, Canceller canceller = { }) override;

    void close() noexcept override;
    bool valid() const noexcept override;

    Socket& socket() noexcept { return socket_; }

private:
    Socket socket_;
};

} // namespace taskpp
