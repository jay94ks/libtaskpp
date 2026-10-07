#pragma once
// HTTP/1.x messages: requests, responses, headers, URLs. All names live in
// `taskpp::http`.
//
// A message body is a `Body`: buffered bytes or a data pipe
// (`Body::fromPipe`). `Form`, `UrlEncodedForm` and `Json` are codecs over that
// body, reachable through the `to*()`/`set*()` helpers below.
#include <taskpp/Config.hpp>
#include <taskpp/http/Body.hpp>
#include <taskpp/http/Form.hpp>
#include <taskpp/http/Json.hpp>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace taskpp::http {

/** A header field: original-case name + value (lookup is case-insensitive). */
struct Header {
    std::string name;
    std::string value;
};

using Headers = std::vector<Header>;

/** Case-insensitive header lookup; empty string when absent. */
std::string headerValue(const Headers& headers, const std::string& name) noexcept;

/** True when any field `name` carries `token` (comma-separated, any case). */
bool headerHasToken(const Headers& headers, const std::string& name, const std::string& token) noexcept;

/**
 * Header + body access shared by requests and responses: content type,
 * query parameters, and the form/JSON codecs.
 */
class HttpMessage {
public:
    HttpMessage() = default;
    explicit HttpMessage(Headers headers) : headers(std::move(headers)) { }

    Headers headers;
    Body body;

    void setBody(Body newBody) { body = std::move(newBody); }
    void setBody(std::string bytes) { body = Body(std::move(bytes)); }

    /** Parsed `Content-Type`; invalid when the header is missing. */
    MediaType mediaType() const;
    bool isMediaType(std::string_view type, std::string_view subtype) const;

    /** True when the body carries no bytes and no pipe. */
    bool bodyEmpty() const noexcept { return body.empty(); }

    // --- JSON -----------------------------------------------------------
    /**
     * Parses the body as JSON. A pipe body is drained first, so this is
     * always the right call; throws `JsonError` when the result is not valid
     * JSON.
     */
    Task<Json> toJson(Canceller canceller = { }) const;
    /** Serializes `value` into the body and sets `application/json`. */
    void setJson(const Json& value, int indent = -1);

    // --- forms ----------------------------------------------------------
    /** Parses the body as multipart or urlencoded, per `Content-Type`. */
    Task<Form> toForm(Canceller canceller = { }) const;
    /** Serializes `form` and sets `multipart/form-data` with a boundary. */
    void setForm(const Form& form, std::string_view boundary = { });

    Task<UrlEncodedForm> toUrlEncodedForm(Canceller canceller = { }) const;
    /** Serializes `form` and sets `application/x-www-form-urlencoded`. */
    void setUrlEncodedForm(const UrlEncodedForm& form);

    // --- plain text -----------------------------------------------------
    /** Body as text, collecting a pipe first. */
    Task<std::string> toText(Canceller canceller = { }) const;
    /** Buffers the body (no-op unless it is a pipe) and sets `text/plain`. */
    void setText(std::string text);
};

/** A parameter parsed out of a request target's query string. */
std::string queryParam(std::string_view target, std::string_view name);

struct HttpRequest : HttpMessage {
    HttpRequest() = default;
    HttpRequest(std::string requestMethod, std::string requestTarget)
        : method(std::move(requestMethod)), target(std::move(requestTarget)) { }

    std::string method = "GET";
    std::string target = "/";

    /** Query parameter of `target`; empty when absent. */
    std::string query(std::string_view name) const { return queryParam(target, name); }

    /** Every value for a repeated query parameter, in order. */
    std::vector<std::string> queryAll(std::string_view name) const;

    /** Path part of `target`, without the query string. */
    std::string path() const;

    /**
     * Reads a single field, preferring the query string and falling back to a
     * urlencoded body (the usual POST-then-redirect idiom). A pipe body is
     * drained first.
     */
    Task<std::optional<std::string>> formField(std::string_view name,
        Canceller canceller = { }) const;
};

struct HttpResponse : HttpMessage {
    HttpResponse() = default;
    explicit HttpResponse(int status) : status(status) { }
    HttpResponse(int status, std::string bodyBytes) : status(status)
    {
        setBody(std::move(bodyBytes));
    }

    int status = 200;
    std::string reason; // empty = default reason phrase for status.
};

/** Default reason phrase (`"OK"`, `"Not Found"`, ...; `"Unknown"` fallback). */
std::string reasonPhrase(int status);

/** Parsed absolute URI (`scheme://host[:port]/path`). */
struct Url {
    std::string scheme; // "http" or "https".
    std::string host;
    std::uint16_t port = 80;
    std::string path = "/";

    /** Throws `std::invalid_argument` on malformed input. */
    static Url parse(const std::string& url);
};

/** Wire limits; requests/responses beyond them throw `HttpError`. */
struct H1Limits {
    std::size_t maxLineBytes = 8192;
    std::size_t maxHeaders = 100;
    std::size_t maxBodyBytes = 32u * 1024u * 1024u;
};

/** Thrown for malformed messages and limit violations. */
class HttpError : public std::runtime_error {
public:
    explicit HttpError(const std::string& what) : std::runtime_error(what) { }
};

} // namespace taskpp::http