#pragma once
// Message bodies and media types. All names live in `taskpp::http`.
//
// A `Body` is either a buffer or a *pipe* that produces its bytes lazily, one
// chunk at a time. That is the data-pipe half of the API: a handler can answer
// with `Body::fromPipe(...)` and stream a large payload (or an incremental
// generator) without ever holding it in memory, and `Transfer-Encoding:
// chunked` (HTTP/1.1) or DATA frames (HTTP/2) are chosen automatically.
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Task.hpp>

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace taskpp::http {

/** Well-known media types used by the form/JSON helpers. */
inline constexpr std::string_view kJsonMediaType = "application/json";
inline constexpr std::string_view kFormUrlEncodedMediaType = "application/x-www-form-urlencoded";
inline constexpr std::string_view kMultipartFormMediaType = "multipart/form-data";
inline constexpr std::string_view kOctetStreamMediaType = "application/octet-stream";
inline constexpr std::string_view kTextPlainMediaType = "text/plain";

/** A `Content-Type` split into its parts (`type/subtype; key="value"`). */
struct MediaType {
    std::string type; // lowercased, e.g. "application".
    std::string subtype; // lowercased, e.g. "json".
    std::vector<std::pair<std::string, std::string>> params; // keys lowercased

    /** Never throws: unrecognized input yields an invalid (empty) result. */
    static MediaType parse(std::string_view value);

    bool valid() const noexcept { return !type.empty() && !subtype.empty(); }

    /** True when the media range matches, ignoring parameters. */
    bool is(std::string_view type, std::string_view subtype) const noexcept;

    /** Parameter value (unquoted), or an empty string when absent. */
    std::string param(std::string_view name) const;

    /** `"type/subtype"` plus every parameter, re-serialized. */
    std::string str() const;
};

/**
 * The body of a request or response: buffered bytes, or a pipe that produces
 * them on demand.
 *
 * A pipe is a `Task<std::optional<std::string>>`: return the next chunk, or
 * `std::nullopt` when the body is complete. It is consumed exactly once, by
 * whoever sends or collects the body.
 */
class Body {
public:
    using Chunk = std::string;
    using Pipe = std::function<Task<std::optional<Chunk>>(Canceller)>;

    Body() = default;
    // Narrowing constructors stay explicit: an implicit `std::string` -> `Body`
    // conversion would make `body == text` ambiguous.
    explicit Body(std::string bytes) : bytes_(std::move(bytes)) { }
    explicit Body(std::string_view bytes) : bytes_(bytes) { }
    explicit Body(const char* bytes) : bytes_(bytes ? bytes : "") { }

    /** A body produced chunk by chunk. The pipe takes ownership of its state. */
    static Body fromPipe(Pipe pipe);

    /** A pipe over a fixed list of chunks (copied; safe to replay). */
    static Body fromChunks(std::vector<Chunk> chunks);

    bool isPipe() const noexcept { return static_cast<bool>(pipe_); }
    bool isBuffered() const noexcept { return !pipe_; }

    /** True when the size is known up front (everything except a pipe). */
    bool knownSize() const noexcept { return !pipe_; }

    /** Buffered size, or 0 for a pipe. */
    std::size_t size() const noexcept { return bytes_.size(); }

    /** Buffered bytes. Empty (and meaningless) for a pipe. */
    const std::string& bytes() const noexcept { return bytes_; }

    bool empty() const noexcept { return pipe_ ? false : bytes_.empty(); }

    void setBytes(std::string bytes);
    void clear() noexcept;

    // Assignment keeps `message.body = "text"` working without an implicit
    // narrowing constructor.
    Body& operator=(std::string bytes) { return setBytesReturning(std::move(bytes)); }
    Body& operator=(std::string_view bytes) { return setBytesReturning(std::string(bytes)); }
    Body& operator=(const char* bytes) { return setBytesReturning(std::string(bytes ? bytes : "")); }

    /** Next chunk of a pipe, or `std::nullopt` once it is exhausted. */
    Task<std::optional<Chunk>> next(Canceller canceller = { }) const;

    /** Runs the body to completion and returns all bytes. */
    Task<std::string> collect(Canceller canceller = { }) const;

    /** Buffered bodies compare by value; a pipe equals only another pipe. */
    bool operator==(const Body& other) const noexcept
    {
        return isPipe() == other.isPipe() && (!isPipe() && bytes_ == other.bytes_);
    }
    bool operator==(std::string_view text) const noexcept
    {
        return !isPipe() && bytes_ == text;
    }

private:
    Body& setBytesReturning(std::string bytes)
    {
        bytes_ = std::move(bytes);
        pipe_ = nullptr;
        return *this;
    }

    std::string bytes_;
    Pipe pipe_;
};

} // namespace taskpp::http