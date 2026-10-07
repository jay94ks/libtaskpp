#pragma once
// HTTP/1.1 connections: client requests and a serving loop. All names live
// in `taskpp::http`.
//
// Bodies use `Content-Length` on the wire in both directions; `Transfer-Encoding:
// chunked` bodies are decoded on receipt (trailers ignored). `Expect:
// 100-continue` is honoured: the server defers reading the body until the
// application accepts it, and the client transparently steps over interim
// (1xx) responses such as `100 Continue` and `103 Early Hints`.
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Stream.hpp>
#include <taskpp/core/Task.hpp>
#include <taskpp/http/HttpMessage.hpp>
#include <taskpp/socket/Socket.hpp>
#include <taskpp/socket/SocketStream.hpp>
#include <taskpp/tls/Tls.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace taskpp::http {

/** `Task<Response> handler(Request)` -- runs once per request. */
using H1Handler = std::function<Task<HttpResponse>(HttpRequest)>;

/**
 * Consulted when a request carries `Expect: 100-continue`, before its body is
 * read. Return `std::nullopt` to accept (the connection then sends
 * `100 Continue` and reads the body); return a response to reject the request
 * without reading the body (the usual answer is `417 Expectation Failed`).
 */
using H1ExpectDecision = std::function<std::optional<HttpResponse>(const HttpRequest&)>;

/**
 * One HTTP/1.x connection over any `Stream` (plain or TLS). Sequential use:
 * send a message, receive the peer's. Reusable while both sides keep the
 * connection alive.
 */
class H1Connection {
public:
    explicit H1Connection(std::unique_ptr<Stream> stream, H1Limits limits = { });

    H1Connection(H1Connection&&) noexcept = default;
    H1Connection& operator=(H1Connection&&) noexcept = default;

    Task<void> sendRequest(const HttpRequest& request, Canceller canceller = { });
    Task<HttpResponse> recvResponse(Canceller canceller = { });

    /**
     * Reads the next request. When it carries `Expect: 100-continue` and a
     * body is expected, `expect` decides: accepting sends `100 Continue` and
     * reads the body; rejecting fills `rejected` with the response to send
     * instead and returns a bodyless request. After a rejection the peer's
     * body is still on the wire, so the connection must not be reused.
     */
    Task<HttpRequest> recvRequest(Canceller canceller = { });
    Task<HttpRequest> recvRequest(Canceller canceller, H1ExpectDecision expect,
        HttpResponse* rejected = nullptr);

    /** True when the last `recvRequest` turned an `Expect` down. */
    bool expectRejected() const noexcept { return expectRejected_; }
    Task<void> sendResponse(const HttpResponse& response, bool keepAlive, Canceller canceller = { });

    /** True when the last exchange left the connection reusable. */
    bool keepAlive() const noexcept { return keepAlive_; }

    /** HTTP version of the last received head (`"HTTP/1.1"` / `"HTTP/1.0"`). */
    const std::string& lastVersion() const noexcept { return lastVersion_; }

    /**
     * Interim (1xx) responses that arrived before the final one, oldest
     * first. Cleared by every `recvResponse`. `101 Switching Protocols` is
     * final and therefore reported through the returned response.
     */
    const std::vector<HttpResponse>& interimResponses() const noexcept { return interim_; }

    void close() noexcept;

private:
    std::unique_ptr<Stream> stream_;
    H1Limits limits_;
    std::string pending_; // buffered but unconsumed bytes.
    std::string lastVersion_ = "HTTP/1.1";
    std::vector<HttpResponse> interim_;
    bool lastHeadOnly_ = false; // last request (either side) was HEAD.
    bool expectRejected_ = false; // last request turned an Expect down.
    bool keepAlive_ = true;
};

/** One-shot client: connects, sends one request, reads one response. */
class H1Client {
public:
    /** `url` must use the `http` scheme (`https` needs a TLS stream). */
    static Task<HttpResponse> request(const std::string& method, const std::string& url,
        Headers headers = { }, const std::string& body = { }, Canceller canceller = { });

    static Task<HttpResponse> get(const std::string& url, Canceller canceller = { });
    static Task<HttpResponse> post(const std::string& url, const std::string& body,
        const std::string& contentType = "application/octet-stream", Canceller canceller = { });

    /**
     * Same, but over TLS for `https://` URLs (`http://` ignores `tls`).
     * `tls.serverName` defaults to the URL host when empty.
     */
    static Task<HttpResponse> request(const std::string& method, const std::string& url,
        Headers headers, const std::string& body, tls::TlsConfig tls, Canceller canceller = { });
};

/**
 * A serving loop over an already-bound `Socket`. Each connection runs as a
 * worker task; requests on one connection are served sequentially with
 * keep-alive. Handler exceptions become `500`; protocol errors close the
 * connection (after a best-effort `400`).
 */
class H1Server {
public:
    explicit H1Server(Socket listener, H1Limits limits = { });

    /**
     * Accepts until `canceller` fires. `expect` decides requests that carry
     * `Expect: 100-continue`; without it such requests are accepted.
     */
    Task<void> serve(H1Handler handler, Canceller canceller = { });
    Task<void> serve(H1Handler handler, Canceller canceller, H1ExpectDecision expect);

    void close() noexcept;

private:
    Socket listener_;
    H1Limits limits_;
};

} // namespace taskpp::http
