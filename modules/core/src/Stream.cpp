// Stream: the shared readExact loop (transport-independent).
#include <taskpp/core/Stream.hpp>

namespace taskpp {

Task<void> Stream::readExact(std::span<char> buffer, Canceller canceller) {
    std::size_t done = 0;
    while (done < buffer.size()) {
        const std::size_t n = co_await readSome(buffer.subspan(done), canceller);
        if (n == 0) {
            throw SocketClosed("stream: orderly shutdown before the bytes arrived.");
        }
        done += n;
    }
    co_return;
}

} // namespace taskpp
