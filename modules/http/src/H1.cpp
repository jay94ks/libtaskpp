// H1: framing, connections, one-shot client, serving loop.
#include <taskpp/http/H1.hpp>
#include <taskpp/tls/Tls.hpp>

#include <taskpp/core/Worker.hpp>

#include <cctype>
#include <charconv>
#include <cstring>
#include <stdexcept>

namespace taskpp::http {
using namespace taskpp::tls;
namespace {

constexpr std::size_t kReadChunk = 8192;

bool isHttp11(const std::string& version) noexcept {
    return version == "HTTP/1.1";
}

bool isHttp10(const std::string& version) noexcept {
    return version == "HTTP/1.0";
}

// Request/response keep-alive from version + Connection header.
bool peerKeepsAlive(const std::string& version, const Headers& headers, bool isRequest) {
    const bool close = headerHasToken(headers, "connection", "close");
    const bool keep = headerHasToken(headers, "connection", "keep-alive");
    if (isHttp11(version)) {
        return !close;
    }
    if (isHttp10(version)) {
        return keep && !close;
    }
    (void) isRequest;
    return false;
}

void setHeader(Headers& headers, const std::string& name, const std::string& value) {
    for (auto& h : headers) {
        if (h.name.size() == name.size()
            && std::equal(h.name.begin(), h.name.end(), name.begin(),
                [](char a, char b) {
                    return std::tolower(static_cast<unsigned char>(a))
                        == std::tolower(static_cast<unsigned char>(b));
                })) {
            h.value = value;
            return;
        }
    }
    headers.push_back({ name, value });
}

bool hasHeader(const Headers& headers, const std::string& name) {
    return !headerValue(headers, name).empty();
}

long long parseContentLength(const Headers& headers) {
    bool seen = false;
    long long value = 0;
    for (const auto& h : headers) {
        if (!(h.name.size() == 14
            && std::equal(h.name.begin(), h.name.end(), "content-length",
                [](char a, char b) {
                    return std::tolower(static_cast<unsigned char>(a))
                        == std::tolower(static_cast<unsigned char>(b));
                }))) {
            continue;
        }
        if (h.value.empty()) {
            throw HttpError("empty Content-Length.");
        }
        long long parsed = 0;
        for (char c : h.value) {
            if (c < '0' || c > '9') {
                throw HttpError("bad Content-Length.");
            }
            parsed = parsed * 10 + (c - '0');
            if (parsed > static_cast<long long>(512u * 1024u * 1024u)) {
                throw HttpError("Content-Length absurd.");
            }
        }
        if (seen && parsed != value) {
            throw HttpError("conflicting Content-Length.");
        }
        seen = true;
        value = parsed;
    }
    return seen ? value : -1;
}

struct Head {
    bool isRequest = true;
    std::string method;
    std::string target;
    std::string version;
    int status = 0;
    std::string reason;
    Headers headers;
};

std::string serializeHead(const Head& head, const std::string& body, bool headOnly) {
    std::string out;
    if (head.isRequest) {
        out += head.method;
        out += ' ';
        out += head.target.empty() ? "/" : head.target;
        out += " HTTP/1.1\r\n";
    }
    else {
        out += "HTTP/1.1 ";
        out += std::to_string(head.status);
        out += ' ';
        out += head.reason.empty() ? reasonPhrase(head.status) : head.reason;
        out += "\r\n";
    }
    for (const auto& h : head.headers) {
        out += h.name;
        out += ": ";
        out += h.value;
        out += "\r\n";
    }
    out += "\r\n";
    if (!headOnly) {
        out += body;
    }
    return out;
}

bool statusAllowsBody(int status) noexcept {
    if (status < 200) {
        return false;
    }
    return status != 204 && status != 304;
}

} // namespace

// ------------------------------------------------------------- H1Connection

H1Connection::H1Connection(std::unique_ptr<Stream> stream, H1Limits limits)
    : stream_(std::move(stream)), limits_(limits) {
    if (!stream_) {
        throw std::invalid_argument("H1Connection needs a stream.");
    }
}

void H1Connection::close() noexcept {
    if (stream_) {
        stream_->close();
    }
    keepAlive_ = false;
}

// ------------------------------------------------------------ body writing

namespace {

std::string toHex(std::size_t value) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    if (value == 0) {
        return "0";
    }
    while (value > 0) {
        out += kHex[value & 0x0F];
        value >>= 4;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

/**
 * Sends a message head plus its body. A buffered body goes out with
 * `Content-Length`; a pipe body has no known length, so HTTP/1.1 falls back to
 * `Transfer-Encoding: chunked` (RFC 9112 7.1) unless the caller already set a
 * length. An explicit `Content-Length` on a pipe is trusted as an upper bound:
 * we still stream, but stop once it is reached.
 */
Task<void> writeMessage(Stream* stream, Head& head, const Body& body, bool headOnly,
    Canceller canceller) {
    const bool hasLength = hasHeader(head.headers, "content-length");
    const bool chunked = !hasLength && body.isPipe()
        && !headerHasToken(head.headers, "transfer-encoding", "chunked");
    if (chunked) {
        setHeader(head.headers, "Transfer-Encoding", "chunked");
    }
    else if (!hasLength) {
        setHeader(head.headers, "Content-Length", std::to_string(body.size()));
    }

    const std::string headWire = serializeHead(head, { }, headOnly);
    co_await stream->write(std::span(headWire.data(), headWire.size()), canceller);
    if (headOnly || body.empty()) {
        co_return;
    }

    if (!body.isPipe()) {
        const std::string& bytes = body.bytes();
        co_await stream->write(std::span(bytes.data(), bytes.size()), std::move(canceller));
        co_return;
    }

    std::size_t remaining = hasLength
        ? static_cast<std::size_t>(std::stoull(headerValue(head.headers, "content-length"))) : 0;
    const bool bounded = hasLength;
    while (true) {
        const auto chunk = co_await body.next(canceller);
        if (!chunk) {
            break;
        }
        std::string_view view(*chunk);
        if (bounded) {
            if (remaining == 0) {
                break;
            }
            if (view.size() > remaining) {
                view = view.substr(0, remaining);
            }
            remaining -= view.size();
        }
        if (chunked) {
            std::string frame = toHex(view.size());
            frame += "\r\n";
            frame += view;
            frame += "\r\n";
            co_await stream->write(std::span(frame.data(), frame.size()), canceller);
        }
        else {
            co_await stream->write(std::span(view.data(), view.size()), canceller);
        }
    }
    if (chunked) {
        static const std::string kLast = "0\r\n\r\n";
        co_await stream->write(std::span(kLast.data(), kLast.size()), std::move(canceller));
    }
}

} // namespace

Task<void> H1Connection::sendRequest(const HttpRequest& request, Canceller canceller) {
    Head head;
    head.isRequest = true;
    head.method = request.method.empty() ? "GET" : request.method;
    head.target = request.target.empty() ? "/" : request.target;
    head.headers = request.headers;
    lastHeadOnly_ = head.method == "HEAD";
    co_await writeMessage(stream_.get(), head, request.body, lastHeadOnly_, std::move(canceller));
    co_return;
}

namespace {

// Reads one CRLF-terminated line (bare LF tolerated); strips the terminator.
Task<std::string> readLine(std::unique_ptr<Stream>& stream, std::string& pending,
    const H1Limits& limits, Canceller canceller) {
    while (true) {
        if (const auto nl = pending.find('\n'); nl != std::string::npos) {
            if (nl > limits.maxLineBytes) {
                throw HttpError("header line too long.");
            }
            std::string line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            co_return line;
        }
        if (pending.size() > limits.maxLineBytes) {
            throw HttpError("header line too long.");
        }
        char chunk[kReadChunk];
        const std::size_t n = co_await stream->readSome(std::span(chunk, sizeof(chunk)), canceller);
        if (n == 0) {
            throw HttpError("connection closed mid-head.");
        }
        pending.append(chunk, n);
    }
}

void checkHeaderName(const std::string& name) {
    if (name.empty()) {
        throw HttpError("empty header name.");
    }
    for (char c : name) {
        const auto u = static_cast<unsigned char>(c);
        if (u <= 32 || u == 127 || c == ':') {
            throw HttpError("bad header name.");
        }
    }
}

Task<Head> readHead(std::unique_ptr<Stream>& stream, std::string& pending,
    const H1Limits& limits, bool isRequest, Canceller canceller) {
    Head head;
    head.isRequest = isRequest;

    const std::string first = co_await readLine(stream, pending, limits, canceller);
    if (isRequest) {
        const auto s1 = first.find(' ');
        const auto s2 = first.find(' ', s1 == std::string::npos ? 0 : s1 + 1);
        if (s1 == std::string::npos || s2 == std::string::npos) {
            throw HttpError("bad request line.");
        }
        head.method = first.substr(0, s1);
        head.target = first.substr(s1 + 1, s2 - s1 - 1);
        head.version = first.substr(s2 + 1);
        if (head.method.empty() || head.target.empty() || head.version.compare(0, 5, "HTTP/") != 0) {
            throw HttpError("bad request line.");
        }
    }
    else {
        const auto s1 = first.find(' ');
        if (s1 == std::string::npos) {
            throw HttpError("bad status line.");
        }
        head.version = first.substr(0, s1);
        const auto s2 = first.find(' ', s1 + 1);
        const std::string code = first.substr(s1 + 1, s2 == std::string::npos ? s2 : s2 - s1 - 1);
        if (head.version.compare(0, 5, "HTTP/") != 0 || code.size() != 3) {
            throw HttpError("bad status line.");
        }
        head.status = 0;
        for (char c : code) {
            if (c < '0' || c > '9') {
                throw HttpError("bad status line.");
            }
            head.status = head.status * 10 + (c - '0');
        }
        head.reason = s2 == std::string::npos ? std::string() : first.substr(s2 + 1);
    }

    while (true) {
        const std::string line = co_await readLine(stream, pending, limits, canceller);
        if (line.empty()) {
            break;
        }
        if (line.front() == ' ' || line.front() == '\t') {
            throw HttpError("obsolete line folding rejected.");
        }
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            throw HttpError("header without colon.");
        }
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        const auto vs = value.find_first_not_of(" \t");
        value = vs == std::string::npos ? std::string() : value.substr(vs);
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
            value.pop_back();
        }
        checkHeaderName(name);
        head.headers.push_back({ std::move(name), std::move(value) });
        if (head.headers.size() > limits.maxHeaders) {
            throw HttpError("too many headers.");
        }
    }
    co_return head;
}

// Reads exactly n bytes: pending buffer first, then the stream.
Task<std::string> readFixed(std::unique_ptr<Stream>& stream, std::string& pending,
    std::size_t n, const H1Limits& limits, Canceller canceller) {
    if (n > limits.maxBodyBytes) {
        throw HttpError("body too large.");
    }
    std::string out;
    out.reserve(n);
    const std::size_t fromPending = std::min(pending.size(), n);
    out.append(pending.data(), fromPending);
    pending.erase(0, fromPending);
    while (out.size() < n) {
        char chunk[kReadChunk];
        const std::size_t want = std::min<std::size_t>(sizeof(chunk), n - out.size());
        const std::size_t got = co_await stream->readSome(std::span(chunk, want), canceller);
        if (got == 0) {
            throw HttpError("connection closed mid-body.");
        }
        out.append(chunk, got);
    }
    co_return out;
}

unsigned long parseChunkSize(const std::string& line) {
    std::string digits = line;
    if (const auto semi = digits.find(';'); semi != std::string::npos) {
        digits.erase(semi);
    }
    if (digits.empty() || digits.size() > 16) {
        throw HttpError("bad chunk size.");
    }
    unsigned long size = 0;
    for (char c : digits) {
        size *= 16;
        if (c >= '0' && c <= '9') {
            size += static_cast<unsigned long>(c - '0');
        }
        else if (c >= 'a' && c <= 'f') {
            size += static_cast<unsigned long>(c - 'a' + 10);
        }
        else if (c >= 'A' && c <= 'F') {
            size += static_cast<unsigned long>(c - 'A' + 10);
        }
        else {
            throw HttpError("bad chunk size.");
        }
    }
    return size;
}

Task<std::string> readChunked(std::unique_ptr<Stream>& stream, std::string& pending,
    const H1Limits& limits, Canceller canceller) {
    std::string out;
    while (true) {
        const unsigned long size = parseChunkSize(co_await readLine(stream, pending, limits, canceller));
        if (size == 0) {
            // Trailers: read until the empty line, then done.
            while (!(co_await readLine(stream, pending, limits, canceller)).empty()) {
            }
            break;
        }
        if (out.size() + size > limits.maxBodyBytes) {
            throw HttpError("body too large.");
        }
        out += co_await readFixed(stream, pending, size, limits, canceller);
        if (!(co_await readLine(stream, pending, limits, canceller)).empty()) {
            throw HttpError("chunk without CRLF.");
        }
    }
    co_return out;
}

Task<std::string> readUntilClose(std::unique_ptr<Stream>& stream, std::string& pending,
    const H1Limits& limits, Canceller canceller) {
    std::string out = std::move(pending);
    pending.clear();
    while (true) {
        char chunk[kReadChunk];
        const std::size_t n = co_await stream->readSome(std::span(chunk, sizeof(chunk)), canceller);
        if (n == 0) {
            break;
        }
        if (out.size() + n > limits.maxBodyBytes) {
            throw HttpError("body too large.");
        }
        out.append(chunk, n);
    }
    co_return out;
}

bool isChunked(const Headers& headers) noexcept {
    return headerHasToken(headers, "transfer-encoding", "chunked");
}

// RFC 9110 15: 1xx is interim except 101, which switches protocols for good.
bool isInterim(unsigned status) noexcept {
    return status >= 100 && status < 200 && status != 101;
}

// True when the request head promises a body that `Expect: 100-continue` gates.
bool expectsBody(const Head& head) noexcept {
    return isChunked(head.headers) || parseContentLength(head.headers) > 0;
}

} // namespace

Task<HttpResponse> H1Connection::recvResponse(Canceller canceller) {
    interim_.clear();
    Head head = co_await readHead(stream_, pending_, limits_, false, canceller);
    while (isInterim(head.status)) {
        // Interim responses are informational; keep them for the application
        // and keep reading until a final one shows up (RFC 9110 15.2).
        HttpResponse note;
        note.status = head.status;
        note.reason = std::move(head.reason);
        note.headers = std::move(head.headers);
        interim_.push_back(std::move(note));
        head = co_await readHead(stream_, pending_, limits_, false, canceller);
    }

    HttpResponse response;
    response.status = head.status;
    response.reason = std::move(head.reason);
    response.headers = std::move(head.headers);

    const bool headOnly = lastHeadOnly_;
    if (headOnly || !statusAllowsBody(response.status)) {
        response.body.clear();
    }
    else if (isChunked(response.headers)) {
        response.body = co_await readChunked(stream_, pending_, limits_, canceller);
    }
    else if (const long long length = parseContentLength(response.headers); length >= 0) {
        response.body = co_await readFixed(stream_, pending_, static_cast<std::size_t>(length), limits_, canceller);
    }
    else {
        response.body = co_await readUntilClose(stream_, pending_, limits_, canceller);
        keepAlive_ = false;
        co_return response;
    }

    keepAlive_ = peerKeepsAlive("HTTP/1.1", response.headers, false);
    co_return response;
}

Task<HttpRequest> H1Connection::recvRequest(Canceller canceller) {
    co_return co_await recvRequest(std::move(canceller), H1ExpectDecision { }, nullptr);
}

Task<HttpRequest> H1Connection::recvRequest(Canceller canceller, H1ExpectDecision expect,
    HttpResponse* rejected) {
    expectRejected_ = false;
    Head head = co_await readHead(stream_, pending_, limits_, true, canceller);

    // Decided before the head is dismantled: both tests read its headers.
    const bool gated = headerHasToken(head.headers, "expect", "100-continue")
        && expectsBody(head);

    HttpRequest request;
    request.method = std::move(head.method);
    request.target = std::move(head.target);
    request.headers = std::move(head.headers);

    if (gated && expect) {
        // The peer is waiting for permission, so the body must not be read
        // until the application has decided (RFC 9110 10.1.1).
        if (const auto answer = expect(request)) {
            if (rejected) {
                *rejected = *answer;
            }
            keepAlive_ = false; // the body stays on the wire; do not reuse.
            expectRejected_ = true;
            lastVersion_ = head.version;
            co_return request;
        }
    }
    if (gated) {
        static const std::string kContinue = "HTTP/1.1 100 Continue\r\n\r\n";
        co_await stream_->write(std::span(kContinue.data(), kContinue.size()), canceller);
    }

    if (isChunked(request.headers)) {
        request.body = co_await readChunked(stream_, pending_, limits_, canceller);
    }
    else if (const long long length = parseContentLength(request.headers); length > 0) {
        request.body = co_await readFixed(stream_, pending_, static_cast<std::size_t>(length), limits_, canceller);
    }

    keepAlive_ = peerKeepsAlive(head.version, request.headers, true);
    lastVersion_ = head.version;
    lastHeadOnly_ = request.method == "HEAD";
    co_return request;
}

Task<void> H1Connection::sendResponse(const HttpResponse& response, bool keepAlive, Canceller canceller) {
    Head head;
    head.isRequest = false;
    head.status = response.status;
    head.reason = response.reason;
    head.headers = response.headers;
    if (!hasHeader(head.headers, "connection")) {
        setHeader(head.headers, "Connection", keepAlive ? "keep-alive" : "close");
    }
    keepAlive_ = keepAlive;
    co_await writeMessage(stream_.get(), head, response.body, lastHeadOnly_, std::move(canceller));
    co_return;
}

// ------------------------------------------------------------- client

Task<HttpResponse> H1Client::request(const std::string& method, const std::string& url,
    Headers headers, const std::string& body, Canceller canceller) {
    const Url parsed = Url::parse(url);
    if (parsed.scheme != "http") {
        throw std::logic_error("H1Client needs http:// (https requires a TLS stream).");
    }

    Socket socket = co_await Socket::connect(parsed.host, parsed.port, canceller);
    H1Connection conn(std::make_unique<SocketStream>(std::move(socket)));

    HttpRequest request;
    request.method = method;
    request.target = parsed.path;
    request.headers = std::move(headers);
    request.body = body;
    if (!hasHeader(request.headers, "host")) {
        const bool standard = parsed.port == 80;
        request.headers.push_back({ "Host",
            standard ? parsed.host : parsed.host + ":" + std::to_string(parsed.port) });
    }
    if (!hasHeader(request.headers, "connection")) {
        request.headers.push_back({ "Connection", "close" });
    }

    co_await conn.sendRequest(request, canceller);
    HttpResponse response = co_await conn.recvResponse(canceller);
    conn.close();
    co_return response;
}

Task<HttpResponse> H1Client::get(const std::string& url, Canceller canceller) {
    HttpResponse response = co_await request("GET", url, { }, { }, std::move(canceller));
    co_return response;
}

Task<HttpResponse> H1Client::post(const std::string& url, const std::string& body,
    const std::string& contentType, Canceller canceller) {
    Headers headers;
    headers.push_back({ "Content-Type", contentType });
    HttpResponse response = co_await request("POST", url, std::move(headers), body, std::move(canceller));
    co_return response;
}

Task<HttpResponse> H1Client::request(const std::string& method, const std::string& url,
    Headers headers, const std::string& body, TlsConfig tls, Canceller canceller) {
    const Url parsed = Url::parse(url);
    if (parsed.scheme == "http") {
        HttpResponse response = co_await request(method, url, std::move(headers), body, std::move(canceller));
        co_return response;
    }
    if (tls.serverName.empty()) {
        tls.serverName = parsed.host;
    }
    Socket raw = co_await Socket::connect(parsed.host, parsed.port, canceller);
    TlsStream tlsStream = co_await TlsStream::connect(std::move(raw), std::move(tls), canceller);
    H1Connection conn(std::make_unique<TlsStream>(std::move(tlsStream)));

    HttpRequest request;
    request.method = method;
    request.target = parsed.path;
    request.headers = std::move(headers);
    request.body = body;
    if (!hasHeader(request.headers, "host")) {
        const bool standard = parsed.port == 443;
        request.headers.push_back({ "Host",
            standard ? parsed.host : parsed.host + ":" + std::to_string(parsed.port) });
    }
    if (!hasHeader(request.headers, "connection")) {
        request.headers.push_back({ "Connection", "close" });
    }
    co_await conn.sendRequest(request, canceller);
    HttpResponse response = co_await conn.recvResponse(canceller);
    conn.close();
    co_return response;
}

// ------------------------------------------------------------- server

namespace {

constexpr int kMaxKeepAliveRequests = 100;

Task<void> serveOne(Socket socket, H1Handler handler, H1Limits limits,
    H1ExpectDecision expect) {
    H1Connection conn(std::make_unique<SocketStream>(std::move(socket)), limits);
    int served = 0;
    try {
        while (served < kMaxKeepAliveRequests) {
            HttpRequest request;
            bool headOk = false;
            try {
                HttpResponse rejected;
                request = co_await conn.recvRequest({ }, expect, &rejected);
                headOk = true;
                if (conn.expectRejected()) {
                    // `Expect: 100-continue` turned down: answer and hang up,
                    // the unread body would desynchronise the connection.
                    try {
                        co_await conn.sendResponse(rejected, false, { });
                    }
                    catch (...) {
                    }
                    break;
                }
            }
            catch (const HttpError&) {
                headOk = false;
            }
            if (!headOk) {
                try {
                    HttpResponse bad;
                    bad.status = 400;
                    bad.body = "Bad Request";
                    co_await conn.sendResponse(bad, false, { });
                }
                catch (...) {
                }
                break;
            }

            const std::string version = conn.lastVersion();
            if (version != "HTTP/1.1" && version != "HTTP/1.0") {
                try {
                    HttpResponse unsupported;
                    unsupported.status = 505;
                    unsupported.body = "HTTP Version Not Supported";
                    co_await conn.sendResponse(unsupported, false, { });
                }
                catch (...) {
                }
                break;
            }

            const bool headOnly = request.method == "HEAD";
            HttpResponse response;
            try {
                response = co_await handler(std::move(request));
            }
            catch (...) {
                response.status = 500;
                response.body = "Internal Server Error";
            }

            const bool keep = conn.keepAlive()
                && !headerHasToken(response.headers, "connection", "close")
                && (version == "HTTP/1.1" || headerHasToken(response.headers, "connection", "keep-alive"));
            if (headOnly) {
                response.body.clear();
            }
            bool sent = false;
            try {
                co_await conn.sendResponse(response, keep, { });
                sent = true;
            }
            catch (...) {
            }
            if (!sent || !keep) {
                break;
            }
            ++served;
        }
    }
    catch (...) {
        // read errors and cancellations: just close.
    }
    conn.close();
    co_return;
}

} // namespace

H1Server::H1Server(Socket listener, H1Limits limits)
    : listener_(std::move(listener)), limits_(limits) { }

void H1Server::close() noexcept {
    listener_.close();
}

Task<void> H1Server::serve(H1Handler handler, Canceller canceller) {
    co_await serve(std::move(handler), std::move(canceller), H1ExpectDecision { });
}

Task<void> H1Server::serve(H1Handler handler, Canceller canceller, H1ExpectDecision expect) {
    auto worker = Worker::currentWorker();
    if (!worker) {
        worker = Worker::defaultWorker();
    }
    while (!canceller.isTriggered()) {
        Socket conn;
        try {
            conn = co_await listener_.accept(canceller);
        }
        catch (const OperationCanceled&) {
            break;
        }
        try {
            worker->push(serveOne(std::move(conn), handler, limits_, expect));
        }
        catch (...) {
            // push failed (shutting down): drop the connection.
        }
    }
    listener_.close();
    co_return;
}

} // namespace taskpp::http
