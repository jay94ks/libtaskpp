#pragma once
// A small JSON value type: parse, inspect, serialize. All names live in
// `taskpp::http`.
#include <taskpp/http/Body.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace taskpp::http {

/** Thrown for malformed JSON documents. */
class JsonError : public std::runtime_error {
public:
    explicit JsonError(const std::string& what) : std::runtime_error("json: " + what) { }
};

/**
 * A JSON document node (RFC 8259). Objects keep their keys sorted, so
 * serializing the same value twice always yields the same bytes.
 *
 * Numbers are stored as a `double` plus, when the value was written as an
 * integer, the exact `int64_t`, so integers round-trip without precision loss.
 */
class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };
    using Array = std::vector<Json>;
    using Object = std::map<std::string, Json>;

    Json() = default;
    Json(std::nullptr_t) { }
    Json(bool value) : type_(Type::Bool), bool_(value) { }
    Json(int value) : Json(static_cast<long long>(value)) { }
    Json(long long value) : type_(Type::Number), isInt_(true), int_(value) { }
    Json(double value) : type_(Type::Number), number_(value) { }
    Json(const char* value) : type_(Type::String), string_(value ? value : "") { }
    Json(std::string value) : type_(Type::String), string_(std::move(value)) { }
    Json(std::string_view value) : type_(Type::String), string_(value) { }
    Json(Array value) : type_(Type::Array), array_(std::move(value)) { }
    Json(Object value) : type_(Type::Object), object_(std::move(value)) { }

    static Json array() { return Json(Array {}); }
    static Json object() { return Json(Object {}); }

    Type type() const noexcept { return type_; }
    bool isNull() const noexcept { return type_ == Type::Null; }
    bool isBool() const noexcept { return type_ == Type::Bool; }
    bool isNumber() const noexcept { return type_ == Type::Number; }
    bool isString() const noexcept { return type_ == Type::String; }
    bool isArray() const noexcept { return type_ == Type::Array; }
    bool isObject() const noexcept { return type_ == Type::Object; }
    /** True for a number written without a fraction or exponent. */
    bool isInteger() const noexcept { return type_ == Type::Number && isInt_; }

    bool asBool(bool fallback = false) const noexcept { return isBool() ? bool_ : fallback; }
    double asNumber(double fallback = 0.0) const noexcept {
        return isNumber() ? (isInt_ ? static_cast<double>(int_) : number_) : fallback;
    }
    long long asInt(long long fallback = 0) const noexcept {
        return isNumber() ? (isInt_ ? int_ : static_cast<long long>(number_)) : fallback;
    }
    /** The string value, or an empty string for any other type. */
    const std::string& asString() const noexcept { return string_; }

    /** Element count for arrays/objects, 0 otherwise. */
    std::size_t size() const noexcept;
    bool empty() const noexcept { return size() == 0; }

    /** Object member; a shared null node when absent (never inserts). */
    const Json& operator[](std::string_view key) const;
    /** Object member, creating a null entry when absent. */
    Json& operator[](std::string_view key);
    /** Array element; a shared null node when out of range. */
    const Json& at(std::size_t index) const;

    bool contains(std::string_view key) const;
    void erase(std::string_view key);

    void push_back(Json value);
    const Array& items() const noexcept { return array_; }
    Array& items() noexcept { return array_; }
    const Object& members() const noexcept { return object_; }
    Object& members() noexcept { return object_; }

    /** Serialized form. `indent < 0` is compact, `0` puts each member on its
     *  own line, `n > 0` pretty-prints with that many spaces per level. */
    std::string dump(int indent = -1) const;

    /** Parses a document; throws `JsonError` on malformed input. */
    static Json parse(std::string_view text);

    /** `parse`, or `std::nullopt` when the text is not valid JSON. */
    static std::optional<Json> tryParse(std::string_view text) noexcept;

    bool operator==(const Json& other) const;

private:
    void dumpInto(std::string& out, int indent, int depth) const;

    Type type_ = Type::Null;
    bool bool_ = false;
    bool isInt_ = false;
    long long int_ = 0;
    double number_ = 0.0;
    std::string string_;
    Array array_;
    Object object_;
};

} // namespace taskpp::http