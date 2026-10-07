// SocketStream: Stream over a connected Socket.
#include <taskpp/socket/SocketStream.hpp>

namespace taskpp {

SocketStream::SocketStream(Socket socket) noexcept : socket_(std::move(socket)) { }

Task<void> SocketStream::write(std::span<const char> data, Canceller canceller) {
    co_await socket_.sendAll(data, std::move(canceller));
    co_return;
}

Task<std::size_t> SocketStream::readSome(std::span<char> buffer, Canceller canceller) {
    co_return co_await socket_.recvSome(buffer, std::move(canceller));
}

void SocketStream::close() noexcept {
    socket_.close();
}

bool SocketStream::valid() const noexcept {
    return socket_.valid();
}

} // namespace taskpp
