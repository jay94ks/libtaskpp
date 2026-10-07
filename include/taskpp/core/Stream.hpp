#pragma once
// Byte-stream abstraction: anything layered (H1/H2/TLS) runs on it.
// All names live in `taskpp`.
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Task.hpp>

#include <cstddef>
#include <memory>
#include <span>

namespace taskpp {

/**
 * An async byte stream. `readSome` returns 0 only on orderly EOF;
 * `readExact` throws `SocketClosed` on early EOF.
 */
class Stream {
public:
    virtual ~Stream() = default;

    virtual Task<void> write(std::span<const char> data, Canceller canceller = { }) = 0;
    virtual Task<std::size_t> readSome(std::span<char> buffer, Canceller canceller = { }) = 0;

    Task<void> readExact(std::span<char> buffer, Canceller canceller = { });

    virtual void close() noexcept = 0;
    virtual bool valid() const noexcept = 0;
};

} // namespace taskpp
