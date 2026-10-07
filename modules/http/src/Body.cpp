// Body (data pipe) and MediaType.
#include <taskpp/http/Body.hpp>

#include <algorithm>
#include <cctype>

namespace taskpp::http {
namespace {

std::string lowerCopy(std::string_view s) {
    std::string out(s);
    for (auto& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
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
    // Also eats CR/LF so it works on raw header lines as well as on values.
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

// Drops one layer of surrounding double quotes.
std::string_view unquote(std::string_view s) noexcept {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

} // namespace

MediaType MediaType::parse(std::string_view value) {
    MediaType out;
    std::string_view rest = trim(value);
    const auto semi = rest.find(';');
    std::string_view head = trim(semi == std::string_view::npos ? rest : rest.substr(0, semi));
    rest = semi == std::string_view::npos ? std::string_view {} : rest.substr(semi + 1);

    const auto slash = head.find('/');
    if (slash == std::string_view::npos) {
        return out; // invalid: no subtype.
    }
    out.type = lowerCopy(head.substr(0, slash));
    out.subtype = lowerCopy(head.substr(slash + 1));
    if (out.type.empty() || out.subtype.empty()) {
        out = MediaType {};
    }

    // Parameters: `; key=value` or `; key="quoted value"`, separated by ';'.
    while (!rest.empty()) {
        const auto next = rest.find(';');
        std::string_view param = trim(next == std::string_view::npos ? rest : rest.substr(0, next));
        rest = next == std::string_view::npos ? std::string_view {} : rest.substr(next + 1);
        if (param.empty()) {
            continue;
        }
        const auto eq = param.find('=');
        if (eq == std::string_view::npos) {
            out.params.emplace_back(lowerCopy(param), std::string());
            continue;
        }
        out.params.emplace_back(lowerCopy(trim(param.substr(0, eq))),
            std::string(unquote(trim(param.substr(eq + 1)))));
    }
    return out;
}

bool MediaType::is(std::string_view type, std::string_view subtype) const noexcept {
    return iequals(this->type, type) && iequals(this->subtype, subtype);
}

std::string MediaType::param(std::string_view name) const {
    for (const auto& [key, value] : params) {
        if (iequals(key, name)) {
            return value;
        }
    }
    return { };
}

std::string MediaType::str() const {
    std::string out = type;
    out += '/';
    out += subtype;
    for (const auto& [key, value] : params) {
        out += "; ";
        out += key;
        out += '=';
        // Quote when the value is not a bare token.
        const bool bare = !value.empty()
            && value.find_first_of(" \t\"()<>@,;:\\/?[]{}=") == std::string::npos;
        if (bare) {
            out += value;
        }
        else {
            out += '"';
            out += value;
            out += '"';
        }
    }
    return out;
}

// ------------------------------------------------------------------- Body

Body Body::fromPipe(Pipe pipe) {
    Body out;
    if (!pipe) {
        return out;
    }
    out.pipe_ = std::move(pipe);
    return out;
}

Body Body::fromChunks(std::vector<Chunk> chunks) {
    auto shared = std::make_shared<std::vector<Chunk>>(std::move(chunks));
    auto index = std::make_shared<size_t>(0);
    return fromPipe([shared, index](Canceller) -> Task<std::optional<Chunk>> {
        if (*index >= shared->size()) {
            co_return std::nullopt;
        }
        co_return (*shared)[(*index)++];
    });
}

void Body::setBytes(std::string bytes) {
    bytes_ = std::move(bytes);
    pipe_ = nullptr;
}

void Body::clear() noexcept {
    bytes_.clear();
    pipe_ = nullptr;
}

Task<std::optional<Body::Chunk>> Body::next(Canceller canceller) const {
    if (!pipe_) {
        if (bytes_.empty()) {
            co_return std::nullopt;
        }
        co_return bytes_;
    }
    co_return co_await pipe_(std::move(canceller));
}

Task<std::string> Body::collect(Canceller canceller) const {
    if (!pipe_) {
        co_return bytes_;
    }
    std::string out;
    while (true) {
        const auto chunk = co_await next(canceller);
        if (!chunk) {
            break;
        }
        out += *chunk;
    }
    co_return out;
}

} // namespace taskpp::http