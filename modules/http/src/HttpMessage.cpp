// HttpMessage: header lookup, body codecs, reason phrases, URL parsing.
#include <taskpp/http/HttpMessage.hpp>

#include <algorithm>
#include <cctype>

namespace taskpp::http {
namespace {

bool asciiCaseEqual(char a, char b) noexcept {
    return a == b || std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
}

bool nameEqual(const std::string& a, const std::string& b) noexcept {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), asciiCaseEqual);
}

} // namespace

std::string headerValue(const Headers& headers, const std::string& name) noexcept {
    for (const auto& h : headers) {
        if (nameEqual(h.name, name)) {
            return h.value;
        }
    }
    return { };
}

bool headerHasToken(const Headers& headers, const std::string& name, const std::string& token) noexcept {
    for (const auto& h : headers) {
        if (!nameEqual(h.name, name)) {
            continue;
        }
        std::size_t i = 0;
        while (i < h.value.size()) {
            while (i < h.value.size() && (h.value[i] == ' ' || h.value[i] == '\t' || h.value[i] == ',')) {
                ++i;
            }
            std::size_t end = i;
            while (end < h.value.size() && h.value[end] != ' ' && h.value[end] != '\t' && h.value[end] != ',') {
                ++end;
            }
            if (end > i && token.size() == end - i
                && std::equal(token.begin(), token.end(), h.value.begin() + i, asciiCaseEqual)) {
                return true;
            }
            i = end;
        }
    }
    return false;
}

namespace {

// Joins `value` onto `headers` as Content-Type, replacing any existing one.
void setContentType(Headers& headers, std::string_view value) {
    for (auto& h : headers) {
        if (nameEqual(h.name, "content-type")) {
            h.value.assign(value);
            return;
        }
    }
    headers.push_back(Header { "Content-Type", std::string(value) });
}

} // namespace

// ------------------------------------------------------------- HttpMessage

MediaType HttpMessage::mediaType() const {
    return MediaType::parse(headerValue(headers, "content-type"));
}

bool HttpMessage::isMediaType(std::string_view type, std::string_view subtype) const {
    return mediaType().is(type, subtype);
}

Task<Json> HttpMessage::toJson(Canceller canceller) const {
    co_return Json::parse(co_await body.collect(std::move(canceller)));
}

void HttpMessage::setJson(const Json& value, int indent) {
    body = Body(value.dump(indent));
    setContentType(headers, kJsonMediaType);
}

Task<Form> HttpMessage::toForm(Canceller canceller) const {
    const MediaType type = mediaType();
    if (!type.valid()) {
        throw FormError("missing Content-Type");
    }
    co_return Form::fromMediaType(type, co_await body.collect(std::move(canceller)));
}

void HttpMessage::setForm(const Form& form, std::string_view boundary) {
    if (boundary.empty()) {
        // Generate once so the header and the body agree on the boundary.
        const std::string b = Form::generateBoundary();
        body = Body(form.encode(b));
        setContentType(headers, form.contentType(b));
        return;
    }
    body = Body(form.encode(boundary));
    setContentType(headers, form.contentType(boundary));
}

Task<UrlEncodedForm> HttpMessage::toUrlEncodedForm(Canceller canceller) const {
    const MediaType type = mediaType();
    if (type.valid() && !type.is("application", "x-www-form-urlencoded")) {
        throw FormError("not urlencoded: " + type.str());
    }
    co_return UrlEncodedForm::decode(co_await body.collect(std::move(canceller)));
}

void HttpMessage::setUrlEncodedForm(const UrlEncodedForm& form) {
    body = Body(form.encode());
    setContentType(headers, kFormUrlEncodedMediaType);
}

Task<std::string> HttpMessage::toText(Canceller canceller) const {
    co_return co_await body.collect(std::move(canceller));
}

void HttpMessage::setText(std::string text) {
    body = Body(std::move(text));
    setContentType(headers, kTextPlainMediaType);
}

// ------------------------------------------------------------ query string

namespace {

std::string_view queryOf(std::string_view target) noexcept {
    const auto q = target.find('?');
    if (q == std::string_view::npos) {
        return {};
    }
    return target.substr(q + 1);
}

} // namespace

std::string queryParam(std::string_view target, std::string_view name) {
    const UrlEncodedForm parsed = UrlEncodedForm::decode(queryOf(target));
    for (const auto& field : parsed.fields()) {
        if (field.first == name) {
            return field.second;
        }
    }
    return { };
}

std::vector<std::string> HttpRequest::queryAll(std::string_view name) const {
    return UrlEncodedForm::decode(queryOf(target)).getAll(name);
}

std::string HttpRequest::path() const {
    const auto q = target.find('?');
    const std::string_view head = q == std::string::npos
        ? std::string_view(target) : std::string_view(target).substr(0, q);
    return head.empty() ? std::string("/") : std::string(head);
}

Task<std::optional<std::string>> HttpRequest::formField(std::string_view name, Canceller canceller) const {
    // Query first, then the body -- the usual POST-then-redirect idiom.
    if (const std::string fromQuery = queryParam(target, name); !fromQuery.empty()) {
        co_return fromQuery;
    }
    const std::string bytes = co_await body.collect(std::move(canceller));
    co_return UrlEncodedForm::decode(bytes).get(name);
}

std::string reasonPhrase(int status) {
    switch (status) {
    case 100:
        return "Continue";
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 204:
        return "No Content";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 304:
        return "Not Modified";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 408:
        return "Request Timeout";
    case 411:
        return "Length Required";
    case 413:
        return "Content Too Large";
    case 414:
        return "URI Too Long";
    case 431:
        return "Request Header Fields Too Large";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 503:
        return "Service Unavailable";
    case 505:
        return "HTTP Version Not Supported";
    default:
        return "Unknown";
    }
}

Url Url::parse(const std::string& url) {
    Url out;
    const auto schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) {
        throw std::invalid_argument("URL misses '://': " + url);
    }
    out.scheme = url.substr(0, schemeEnd);
    for (auto& c : out.scheme) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (out.scheme != "http" && out.scheme != "https") {
        throw std::invalid_argument("unsupported URL scheme: " + out.scheme);
    }
    out.port = out.scheme == "https" ? 443 : 80;

    std::string rest = url.substr(schemeEnd + 3);
    const auto pathBegin = rest.find('/');
    std::string authority = pathBegin == std::string::npos ? rest : rest.substr(0, pathBegin);
    out.path = pathBegin == std::string::npos ? "/" : rest.substr(pathBegin);
    if (out.path.empty()) {
        out.path = "/";
    }

    if (!authority.empty() && authority.front() == '[') {
        // [v6-literal][:port]
        const auto close = authority.find(']');
        if (close == std::string::npos) {
            throw std::invalid_argument("bad IPv6 authority: " + url);
        }
        out.host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') {
                throw std::invalid_argument("bad authority: " + url);
            }
            out.port = static_cast<std::uint16_t>(std::stoi(authority.substr(close + 2)));
        }
    }
    else if (const auto colon = authority.rfind(':'); colon != std::string::npos) {
        out.host = authority.substr(0, colon);
        out.port = static_cast<std::uint16_t>(std::stoi(authority.substr(colon + 1)));
    }
    else {
        out.host = authority;
    }

    if (out.host.empty()) {
        throw std::invalid_argument("URL misses a host: " + url);
    }
    return out;
}

} // namespace taskpp::http