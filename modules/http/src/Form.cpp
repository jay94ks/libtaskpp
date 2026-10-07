// Form and UrlEncodedForm codecs.
#include <taskpp/http/Form.hpp>

#include <algorithm>
#include <cctype>
#include <cstring>

#include <certpp.hpp>

namespace taskpp::http {
namespace {

int hexValue(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

// Folds an already-decoded value back into form bytes, following the WHATWG
// urlencoded byte set: only alphanumerics and `*-._` stay literal, a space
// becomes `+`, everything else is percent-escaped.
void appendBytes(std::string& out, std::string_view raw) {
    static const char* kHex = "0123456789ABCDEF";
    for (const char c : raw) {
        const auto u = static_cast<unsigned char>(c);
        const bool literal = (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z')
            || (u >= '0' && u <= '9') || u == '*' || u == '-' || u == '.' || u == '_';
        if (literal) {
            out += c;
        }
        else if (u == ' ') {
            out += '+';
        }
        else if (c < 0) {
            // A UTF-8 continuation byte: leave the sequence intact.
            out += c;
        }
        else {
            out += '%';
            out += kHex[u >> 4];
            out += kHex[u & 0x0F];
        }
    }
}

bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i]))
            != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string_view trim(std::string_view s) noexcept {
    // Also eats CR: multipart headers are split on '\n', so every line still
    // carries its trailing CR.
    const auto isSpace = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    while (!s.empty() && isSpace(s.front())) {
        s.remove_prefix(1);
    }
    while (!s.empty() && isSpace(s.back())) {
        s.remove_suffix(1);
    }
    return s;
}

// Pulls one `name="value"` parameter out of a part's Content-Disposition.
std::string dispositionParam(std::string_view value, std::string_view key) {
    std::size_t pos = 0;
    while (pos < value.size()) {
        const auto semi = value.find(';', pos);
        std::string_view piece = trim(
            semi == std::string_view::npos ? value.substr(pos) : value.substr(pos, semi - pos));
        pos = semi == std::string_view::npos ? value.size() : semi + 1;
        const auto eq = piece.find('=');
        if (eq == std::string_view::npos) {
            continue;
        }
        if (!iequals(trim(piece.substr(0, eq)), key)) {
            continue;
        }
        std::string_view raw = trim(piece.substr(eq + 1));
        if (raw.size() >= 2 && raw.front() == '"' && raw.back() == '"') {
            // RFC 5987 style: keep the value, drop the quoting.
            raw = raw.substr(1, raw.size() - 2);
        }
        return std::string(raw);
    }
    return { };
}

} // namespace

// --------------------------------------------------------- UrlEncodedForm

void UrlEncodedForm::add(std::string name, std::string value) {
    fields_.emplace_back(std::move(name), std::move(value));
}

void UrlEncodedForm::set(std::string name, std::string value) {
    bool replaced = false;
    for (auto& [key, val] : fields_) {
        if (key == name) {
            val = value;
            replaced = true;
        }
    }
    if (!replaced) {
        fields_.emplace_back(std::move(name), std::move(value));
    }
}

std::optional<std::string> UrlEncodedForm::get(std::string_view name) const {
    for (const auto& [key, value] : fields_) {
        if (key == name) {
            return value;
        }
    }
    return std::nullopt;
}

std::vector<std::string> UrlEncodedForm::getAll(std::string_view name) const {
    std::vector<std::string> out;
    for (const auto& [key, value] : fields_) {
        if (key == name) {
            out.push_back(value);
        }
    }
    return out;
}

bool UrlEncodedForm::has(std::string_view name) const {
    for (const auto& [key, value] : fields_) {
        if (key == name) {
            (void) value;
            return true;
        }
    }
    return false;
}

std::string UrlEncodedForm::encode() const {
    std::string out;
    for (size_t i = 0; i < fields_.size(); ++i) {
        if (i > 0) {
            out += '&';
        }
        appendBytes(out, fields_[i].first);
        out += '=';
        appendBytes(out, fields_[i].second);
    }
    return out;
}

UrlEncodedForm UrlEncodedForm::decode(std::string_view encoded) {
    UrlEncodedForm out;
    size_t pos = 0;
    while (pos < encoded.size()) {
        const auto amp = encoded.find('&', pos);
        std::string_view pair = amp == std::string_view::npos
            ? encoded.substr(pos) : encoded.substr(pos, amp - pos);
        pos = amp == std::string_view::npos ? encoded.size() : amp + 1;
        if (pair.empty()) {
            continue;
        }
        const auto eq = pair.find('=');
        std::string_view rawName = eq == std::string_view::npos ? pair : pair.substr(0, eq);
        std::string_view rawValue = eq == std::string_view::npos ? std::string_view {}
                                                                 : pair.substr(eq + 1);
        out.fields_.emplace_back(unescape(rawName), unescape(rawValue));
    }
    return out;
}

std::string UrlEncodedForm::escape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    appendBytes(out, value);
    return out;
}

std::string UrlEncodedForm::unescape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const char c = value[i];
        if (c == '+') {
            out += ' ';
        }
        else if (c == '%' && i + 2 < value.size()) {
            const int hi = hexValue(value[i + 1]);
            const int lo = hexValue(value[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>((hi << 4) | lo);
                i += 2;
            }
            else {
                out += c; // not a valid escape: keep it verbatim.
            }
        }
        else {
            out += c;
        }
    }
    return out;
}

// ------------------------------------------------------------------- Form

void Form::add(std::string name, std::string value) {
    Part part;
    part.name = std::move(name);
    part.data = std::move(value);
    parts_.push_back(std::move(part));
}

void Form::addFile(std::string name, std::string filename, std::string data,
    std::string contentType) {
    Part part;
    part.name = std::move(name);
    part.filename = std::move(filename);
    part.contentType = std::move(contentType);
    part.data = std::move(data);
    parts_.push_back(std::move(part));
}

const Form::Part* Form::find(std::string_view name) const {
    for (const auto& part : parts_) {
        if (part.name == name) {
            return &part;
        }
    }
    return nullptr;
}

std::vector<const Form::Part*> Form::findAll(std::string_view name) const {
    std::vector<const Form::Part*> out;
    for (const auto& part : parts_) {
        if (part.name == name) {
            out.push_back(&part);
        }
    }
    return out;
}

std::vector<std::string> Form::names() const {
    std::vector<std::string> out;
    out.reserve(parts_.size());
    for (const auto& part : parts_) {
        out.push_back(part.name);
    }
    return out;
}

bool Form::has(std::string_view name) const {
    return find(name) != nullptr;
}

std::optional<std::string> Form::value(std::string_view name) const {
    const Part* part = find(name);
    if (!part) {
        return std::nullopt;
    }
    return part->data;
}

std::string Form::generateBoundary() {
    std::string raw(16, '\0');
    certpp::SByteSpan span(reinterpret_cast<unsigned char*>(raw.data()), raw.size());
    certpp::crypto::CRng::fill(span);
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (const char c : raw) {
        const auto u = static_cast<unsigned char>(c);
        out += kHex[u >> 4];
        out += kHex[u & 0x0F];
    }
    return out;
}

std::string Form::encode(std::string_view boundary) const {
    const std::string b = boundary.empty() ? generateBoundary() : std::string(boundary);
    std::string out;
    for (const auto& part : parts_) {
        out += "--";
        out += b;
        out += "\r\nContent-Disposition: form-data; name=\"";
        out += part.name;
        out += '"';
        if (!part.filename.empty()) {
            out += "; filename=\"";
            out += part.filename;
            out += '"';
        }
        out += "\r\n";
        if (!part.contentType.empty()) {
            out += "Content-Type: ";
            out += part.contentType;
            out += "\r\n";
        }
        out += "\r\n";
        out += part.data;
        out += "\r\n";
    }
    out += "--";
    out += b;
    out += "--\r\n";
    return out;
}

std::string Form::contentType(std::string_view boundary) const {
    const std::string b = boundary.empty() ? generateBoundary() : std::string(boundary);
    return std::string(kMultipartFormMediaType) + "; boundary=" + b;
}

Form Form::decode(std::string_view body, std::string_view boundary) {
    if (boundary.empty()) {
        throw FormError("missing boundary");
    }
    const std::string delimiter = "--" + std::string(boundary);
    Form out;

    size_t pos = body.find(delimiter);
    if (pos == std::string_view::npos) {
        throw FormError("boundary not found");
    }
    pos += delimiter.size();

    while (pos < body.size()) {
        // "--" right after the delimiter marks the closing boundary.
        if (body.compare(pos, 2, "--") == 0) {
            break;
        }
        // Skip the CRLF (or a bare LF) that ends the delimiter line.
        if (body.compare(pos, 2, "\r\n") == 0) {
            pos += 2;
        }
        else if (body.compare(pos, 1, "\n") == 0) {
            ++pos;
        }
        else {
            throw FormError("malformed boundary line");
        }

        const auto headerEnd = body.find("\r\n\r\n", pos);
        if (headerEnd == std::string_view::npos) {
            throw FormError("part without headers");
        }
        const std::string_view rawHeaders = body.substr(pos, headerEnd - pos);

        Part part;
        bool haveDisposition = false;
        size_t lineStart = 0;
        while (lineStart <= rawHeaders.size()) {
            const auto lineEnd = rawHeaders.find('\n', lineStart);
            std::string_view line = trim(rawHeaders.substr(lineStart,
                lineEnd == std::string_view::npos ? std::string_view::npos
                                                  : lineEnd - lineStart));
            lineStart = lineEnd == std::string_view::npos ? rawHeaders.size() + 1 : lineEnd + 1;
            if (line.empty()) {
                continue;
            }
            const auto colon = line.find(':');
            if (colon == std::string_view::npos) {
                continue;
            }
            const std::string_view name = trim(line.substr(0, colon));
            const std::string_view value = trim(line.substr(colon + 1));
            if (iequals(name, "content-disposition")) {
                part.name = dispositionParam(value, "name");
                part.filename = dispositionParam(value, "filename");
                haveDisposition = true;
            }
            else if (iequals(name, "content-type")) {
                part.contentType = std::string(value);
            }
        }
        if (!haveDisposition) {
            throw FormError("part without content-disposition");
        }

        // The part data runs to the CRLF that precedes the next boundary.
        const size_t dataStart = headerEnd + 4;
        const auto nextBoundary = body.find(delimiter, dataStart);
        if (nextBoundary == std::string_view::npos) {
            throw FormError("unterminated part");
        }
        size_t dataEnd = nextBoundary;
        if (dataEnd >= 2 && body.compare(dataEnd - 2, 2, "\r\n") == 0) {
            dataEnd -= 2;
        }
        else if (dataEnd >= 1 && body[dataEnd - 1] == '\n') {
            dataEnd -= 1;
        }
        part.data = std::string(body.substr(dataStart, dataEnd - dataStart));
        out.parts_.push_back(std::move(part));

        pos = nextBoundary + delimiter.size();
    }
    return out;
}

Form Form::fromMediaType(const MediaType& mediaType, std::string_view body) {
    if (mediaType.is("multipart", "form-data")) {
        return decode(body, mediaType.param("boundary"));
    }
    if (mediaType.is("application", "x-www-form-urlencoded")) {
        Form out;
        const UrlEncodedForm decoded = UrlEncodedForm::decode(body);
        for (const auto& [name, value] : decoded.fields()) {
            out.add(name, value);
        }
        return out;
    }
    throw FormError("unsupported media type: " + mediaType.str());
}

} // namespace taskpp::http