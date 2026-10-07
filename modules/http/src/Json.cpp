// Json: a small RFC 8259 value type.
#include <taskpp/http/Json.hpp>

#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace taskpp::http {
namespace {

const Json& nullNode() {
    static const Json instance;
    return instance;
}

void appendEscaped(std::string& out, std::string_view value) {
    out += '"';
    for (size_t i = 0; i < value.size(); ++i) {
        const auto u = static_cast<unsigned char>(value[i]);
        switch (u) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (u < 0x20) {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x", u);
                out += buf;
            }
            else {
                // Bytes >= 0x80 pass through: the input is already UTF-8.
                out += static_cast<char>(u);
            }
            break;
        }
    }
    out += '"';
}

void appendNumber(std::string& out, long long value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%lld", value);
    out += buf;
}

void appendNumber(std::string& out, double value) {
    if (!std::isfinite(value)) {
        out += "null"; // JSON has no NaN/Infinity.
        return;
    }
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%.17g", value);
    out += buf;
}

// ------------------------------------------------------------- parser

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) { }

    Json parseDocument() {
        skipWhitespace();
        Json value = parseValue(0);
        skipWhitespace();
        if (pos_ != text_.size()) {
            fail("trailing characters after the document");
        }
        return value;
    }

private:
    static constexpr int kMaxDepth = 200; // guards against stack exhaustion.

    [[noreturn]] void fail(const char* why) const {
        throw JsonError(std::string(why) + " at offset " + std::to_string(pos_));
    }

    void skipWhitespace() {
        while (pos_ < text_.size()) {
            const char c = text_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++pos_;
            }
            else {
                break;
            }
        }
    }

    char peek() const {
        if (pos_ >= text_.size()) {
            return '\0';
        }
        return text_[pos_];
    }

    bool consume(char c) {
        if (peek() == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    void expect(char c) {
        if (!consume(c)) {
            fail("unexpected character");
        }
    }

    Json parseValue(int depth) {
        if (depth > kMaxDepth) {
            fail("nesting too deep");
        }
        skipWhitespace();
        switch (peek()) {
        case '{':
            return parseObject(depth);
        case '[':
            return parseArray(depth);
        case '"':
            return Json(parseString());
        case 't':
            expectLiteral("true");
            return Json(true);
        case 'f':
            expectLiteral("false");
            return Json(false);
        case 'n':
            expectLiteral("null");
            return Json();
        default:
            return parseNumber();
        }
    }

    void expectLiteral(std::string_view literal) {
        if (text_.substr(pos_, literal.size()) != literal) {
            fail("bad literal");
        }
        pos_ += literal.size();
    }

    Json parseObject(int depth) {
        expect('{');
        Json out = Json::object();
        skipWhitespace();
        if (consume('}')) {
            return out;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                fail("object key must be a string");
            }
            std::string key = parseString();
            skipWhitespace();
            expect(':');
            out.members()[std::move(key)] = parseValue(depth + 1);
            skipWhitespace();
            if (consume(',')) {
                continue;
            }
            expect('}');
            return out;
        }
    }

    Json parseArray(int depth) {
        expect('[');
        Json out = Json::array();
        skipWhitespace();
        if (consume(']')) {
            return out;
        }
        while (true) {
            out.items().push_back(parseValue(depth + 1));
            skipWhitespace();
            if (consume(',')) {
                continue;
            }
            expect(']');
            return out;
        }
    }

    static void appendCodePoint(std::string& out, unsigned long cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        }
        else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
        else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
        else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    unsigned long parseHex4() {
        if (pos_ + 4 > text_.size()) {
            fail("truncated \\u escape");
        }
        unsigned long value = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = text_[pos_++];
            value <<= 4;
            if (c >= '0' && c <= '9') {
                value |= static_cast<unsigned long>(c - '0');
            }
            else if (c >= 'a' && c <= 'f') {
                value |= static_cast<unsigned long>(c - 'a' + 10);
            }
            else if (c >= 'A' && c <= 'F') {
                value |= static_cast<unsigned long>(c - 'A' + 10);
            }
            else {
                fail("bad hex digit in \\u escape");
            }
        }
        return value;
    }

    std::string parseString() {
        expect('"');
        std::string out;
        while (true) {
            if (pos_ >= text_.size()) {
                fail("unterminated string");
            }
            const char c = text_[pos_++];
            if (c == '"') {
                return out;
            }
            if (static_cast<unsigned char>(c) < 0x20) {
                fail("control character in string");
            }
            if (c != '\\') {
                out += c;
                continue;
            }
            if (pos_ >= text_.size()) {
                fail("unterminated escape");
            }
            const char esc = text_[pos_++];
            switch (esc) {
            case '"':
                out += '"';
                break;
            case '\\':
                out += '\\';
                break;
            case '/':
                out += '/';
                break;
            case 'b':
                out += '\b';
                break;
            case 'f':
                out += '\f';
                break;
            case 'n':
                out += '\n';
                break;
            case 'r':
                out += '\r';
                break;
            case 't':
                out += '\t';
                break;
            case 'u': {
                unsigned long cp = parseHex4();
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    // High surrogate: a low surrogate must follow.
                    if (pos_ + 1 < text_.size() && text_[pos_] == '\\' && text_[pos_ + 1] == 'u') {
                        pos_ += 2;
                        const unsigned long low = parseHex4();
                        if (low < 0xDC00 || low > 0xDFFF) {
                            fail("bad low surrogate");
                        }
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    }
                    else {
                        fail("lone high surrogate");
                    }
                }
                else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    fail("lone low surrogate");
                }
                appendCodePoint(out, cp);
                break;
            }
            default:
                fail("unknown escape");
            }
        }
    }

    Json parseNumber() {
        const size_t start = pos_;
        consume('-');
        if (pos_ >= text_.size() || std::isdigit(static_cast<unsigned char>(text_[pos_])) == 0) {
            fail("number expected");
        }
        if (text_[pos_] == '0') {
            ++pos_;
        }
        else {
            while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_])) != 0) {
                ++pos_;
            }
        }
        bool isInt = true;
        if (pos_ < text_.size() && text_[pos_] == '.') {
            isInt = false;
            ++pos_;
            if (pos_ >= text_.size()
                || std::isdigit(static_cast<unsigned char>(text_[pos_])) == 0) {
                fail("fraction needs digits");
            }
            while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_])) != 0) {
                ++pos_;
            }
        }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            isInt = false;
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) {
                ++pos_;
            }
            if (pos_ >= text_.size()
                || std::isdigit(static_cast<unsigned char>(text_[pos_])) == 0) {
                fail("exponent needs digits");
            }
            while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_])) != 0) {
                ++pos_;
            }
        }

        const std::string_view token = text_.substr(start, pos_ - start);
        if (isInt) {
            // std::from_chars is exact and, unlike strtoll, does not report
            // ERANGE for a value that is exactly representable.
            long long value = 0;
            const auto result = std::from_chars(token.data(), token.data() + token.size(), value);
            if (result.ec == std::errc { } && result.ptr == token.data() + token.size()) {
                return Json(value);
            }
            // Out of int64 range: fall through to a double.
        }
        const std::string copy(token);
        return Json(std::strtod(copy.c_str(), nullptr));
    }

    std::string_view text_;
    size_t pos_ = 0;
};

} // namespace

// ------------------------------------------------------------------ Json

std::size_t Json::size() const noexcept {
    if (isArray()) {
        return array_.size();
    }
    if (isObject()) {
        return object_.size();
    }
    return 0;
}

const Json& Json::operator[](std::string_view key) const {
    if (!isObject()) {
        return nullNode();
    }
    const auto it = object_.find(std::string(key));
    return it == object_.end() ? nullNode() : it->second;
}

Json& Json::operator[](std::string_view key) {
    if (!isObject()) {
        type_ = Type::Object;
    }
    return object_[std::string(key)];
}

const Json& Json::at(std::size_t index) const {
    if (!isArray() || index >= array_.size()) {
        return nullNode();
    }
    return array_[index];
}

bool Json::contains(std::string_view key) const {
    return isObject() && object_.find(std::string(key)) != object_.end();
}

void Json::erase(std::string_view key) {
    if (isObject()) {
        object_.erase(std::string(key));
    }
}

void Json::push_back(Json value) {
    if (!isArray()) {
        type_ = Type::Array;
    }
    array_.push_back(std::move(value));
}

std::string Json::dump(int indent) const {
    std::string out;
    dumpInto(out, indent, 0);
    return out;
}

void Json::dumpInto(std::string& out, int indent, int depth) const {
    const bool pretty = indent >= 0;
    const auto newline = [&](int level) {
        if (!pretty) {
            return;
        }
        out += '\n';
        out.append(static_cast<std::size_t>(indent * level), ' ');
    };

    switch (type_) {
    case Type::Null:
        out += "null";
        break;
    case Type::Bool:
        out += bool_ ? "true" : "false";
        break;
    case Type::Number:
        if (isInt_) {
            appendNumber(out, int_);
        }
        else {
            appendNumber(out, number_);
        }
        break;
    case Type::String:
        appendEscaped(out, string_);
        break;
    case Type::Array:
        if (array_.empty()) {
            out += "[]";
            break;
        }
        out += '[';
        for (std::size_t i = 0; i < array_.size(); ++i) {
            if (i > 0) {
                out += ',';
            }
            newline(depth + 1);
            array_[i].dumpInto(out, indent, depth + 1);
        }
        newline(depth);
        out += ']';
        break;
    case Type::Object:
        if (object_.empty()) {
            out += "{}";
            break;
        }
        out += '{';
        {
            std::size_t i = 0;
            for (const auto& [key, value] : object_) {
                if (i > 0) {
                    out += ',';
                }
                newline(depth + 1);
                appendEscaped(out, key);
                out += ':';
                if (pretty) {
                    out += ' ';
                }
                value.dumpInto(out, indent, depth + 1);
                ++i;
            }
        }
        newline(depth);
        out += '}';
        break;
    }
}

Json Json::parse(std::string_view text) {
    return Parser(text).parseDocument();
}

std::optional<Json> Json::tryParse(std::string_view text) noexcept {
    try {
        return parse(text);
    }
    catch (...) {
        return std::nullopt;
    }
}

bool Json::operator==(const Json& other) const {
    if (type_ != other.type_) {
        return false;
    }
    switch (type_) {
    case Type::Null:
        return true;
    case Type::Bool:
        return bool_ == other.bool_;
    case Type::Number:
        return isInt_ == other.isInt_ && asNumber() == other.asNumber();
    case Type::String:
        return string_ == other.string_;
    case Type::Array:
        return array_ == other.array_;
    case Type::Object:
        return object_ == other.object_;
    }
    return false;
}

} // namespace taskpp::http