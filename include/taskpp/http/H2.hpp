#pragma once
// HTTP/2 (RFC 9113 / RFC 7540): framing, multiplexed client and server over
// any Stream. All names live in `taskpp::http`.
//
// Transports: cleartext prior-knowledge (h2c) or TLS with ALPN `h2`.
// The client multiplexes: a single reader pump dispatches frames to per-stream
// state, and up to `min(peer's MAX_CONCURRENT_STREAMS, limits.maxStreams)`
// requests may be in flight at once. Server streams run concurrently on the
// worker. Flow control is enforced both directions; WINDOW_UPDATEs automatic.
// Server push is declined (SETTINGS_ENABLE_PUSH = 0, plus RST_STREAM on any
// PUSH_PROMISE that arrives anyway -- RFC 9113 8.4).
#include <taskpp/core/AsyncMutex.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Channel.hpp>
#include <taskpp/core/Stream.hpp>
#include <taskpp/core/Task.hpp>
#include <taskpp/http/Hpack.hpp>
#include <taskpp/http/HttpMessage.hpp>
#include <taskpp/socket/SocketStream.hpp>
#include <taskpp/tls/Tls.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace taskpp::http {

/** Pseudo-header fields plus the header block, with a `Body`. */
struct H2Request : HttpMessage {
    std::string method = "GET";
    std::string scheme = "http";
    std::string authority;
    std::string path = "/";
};

struct H2Response : HttpMessage {
    H2Response() = default;
    explicit H2Response(int status) : status(status) { }
    H2Response(int status, std::string bodyBytes) : status(status)
    {
        body = Body(std::move(bodyBytes));
    }

    int status = 200;
};

/** A `PUSH_PROMISE` we saw. Pushes are refused, so this is informational. */
struct H2Push {
    uint32_t stream = 0; // the stream that carried the promise.
    uint32_t promised = 0; // the promised (server-initiated) stream id.
    std::string method;
    std::string scheme;
    std::string authority;
    std::string path;
    Headers headers;
};

/** Thrown for connection errors (carries the RFC 7540 error code). */
class H2Error : public std::runtime_error {
public:
    explicit H2Error(const std::string& what, uint32_t code = 2)
        : std::runtime_error("h2: " + what), code_(code) { }

    uint32_t code() const noexcept { return code_; }

    /** True when the request never reached the server and may be retried. */
    bool retryable() const noexcept { return code_ == 7 || code_ == 0; }

private:
    uint32_t code_;
};

/** `Task<H2Response> handler(H2Request)` -- runs once per stream. */
using H2Handler = std::function<Task<H2Response>(H2Request)>;

struct H2Limits {
    std::size_t maxFrameBytes = 16384;
    std::size_t maxHeaderBytes = 65536;
    std::size_t maxStreams = 100;
    uint32_t maxWindowBytes = 65535;
};

/**
 * Client connection over an established stream (handshake already done).
 * Requests may be issued concurrently; the connection stays usable for more.
 */
class H2Connection {
public:
    /**
     * Sends the client preface; expects the server SETTINGS first.
     * `sendMagic` is prior-knowledge h2c only -- never over TLS (RFC 7540 3.2).
     */
    static Task<H2Connection> connect(std::unique_ptr<Stream> stream,
        H2Limits limits = { }, Canceller canceller = { }, bool sendMagic = true);

    H2Connection(H2Connection&&) noexcept;
    H2Connection& operator=(H2Connection&&) noexcept;
    ~H2Connection();

    /** Issues one request. Safe to call concurrently from several tasks. */
    Task<H2Response> request(H2Request req, Canceller canceller = { });

    /** True once the peer's GOAWAY arrived; no further requests are sent. */
    bool goaway() const noexcept;
    /** GOAWAY error code (0 = none). */
    uint32_t goawayCode() const noexcept;
    /** Highest stream id the server said it processed. */
    uint32_t goawayLastStream() const noexcept;
    /** Peer's MAX_CONCURRENT_STREAMS, as advertised in its SETTINGS. */
    uint32_t maxConcurrentStreams() const noexcept;

    /** PUSH_PROMISE headers seen so far (each one was refused). */
    std::vector<H2Push> pushPromises() const;

    void close() noexcept;

private:
    struct State;
    H2Connection() = default;

    std::unique_ptr<State> state_;
};

/** One-shot client: connects, sends one request, reads one response. */
class H2Client {
public:
    /** `http://` runs h2c prior-knowledge; `https://` needs ALPN `h2`. */
    static Task<H2Response> request(const std::string& method, const std::string& url,
        Headers headers = { }, const std::string& body = { }, Canceller canceller = { });

    static Task<H2Response> get(const std::string& url, Canceller canceller = { });
    static Task<H2Response> post(const std::string& url, const std::string& body,
        const std::string& contentType = "application/octet-stream", Canceller canceller = { });

    /**
     * Same, but over TLS for `https://` URLs (ALPN must negotiate `h2`).
     * `tls.serverName` defaults to the URL host when empty.
     */
    static Task<H2Response> request(const std::string& method, const std::string& url,
        Headers headers, const std::string& body, tls::TlsConfig tls, Canceller canceller = { });
};

/** Serving loops. Each accepted transport becomes one H2 session. */
class H2Server {
public:
    /** Cleartext prior-knowledge (client magic + SETTINGS expected). */
    static Task<void> serveH2c(Socket listener, H2Handler handler,
        H2Limits limits = { }, Canceller canceller = { });

    /** TLS: ALPN must have negotiated `h2`, else the connection closes. */
    static Task<void> serveTls(Socket listener, tls::TlsConfig tls, H2Handler handler,
        H2Limits limits = { }, Canceller canceller = { });

private:
    H2Server() = delete;
};

} // namespace taskpp::http
