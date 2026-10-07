#pragma once
// `application/x-www-form-urlencoded` and `multipart/form-data`. All names
// live in `taskpp::http`.
#include <taskpp/http/Body.hpp>

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace taskpp::http {

/** Thrown when a form body cannot be parsed. */
class FormError : public std::runtime_error {
public:
    explicit FormError(const std::string& what) : std::runtime_error("form: " + what) { }
};

/**
 * `application/x-www-form-urlencoded`: ordered name/value pairs, kept in
 * insertion order with duplicates preserved (HTML forms allow repeats).
 */
class UrlEncodedForm {
public:
    using Field = std::pair<std::string, std::string>;

    UrlEncodedForm() = default;
    UrlEncodedForm(std::initializer_list<Field> fields) : fields_(fields) { }

    void add(std::string name, std::string value);
    void set(std::string name, std::string value); // replaces every match
    void clear() noexcept { fields_.clear(); }

    const std::vector<Field>& fields() const noexcept { return fields_; }
    bool empty() const noexcept { return fields_.empty(); }
    std::size_t size() const noexcept { return fields_.size(); }

    /** First value for `name`, or `std::nullopt`. */
    std::optional<std::string> get(std::string_view name) const;
    /** Every value for `name`, in order. */
    std::vector<std::string> getAll(std::string_view name) const;
    bool has(std::string_view name) const;

    /** `a=1&b=2`, percent-escaped. */
    std::string encode() const;

    /** Parses `a=1&b=2`; `+` decodes to space, `%XX` to a byte. */
    static UrlEncodedForm decode(std::string_view encoded);

    /** Percent-escapes one value (`encodeFormComponent`). */
    static std::string escape(std::string_view value);
    static std::string unescape(std::string_view value);

private:
    std::vector<Field> fields_;
};

/**
 * `multipart/form-data` (RFC 7578): an ordered list of parts, each either a
 * plain field or a file upload carrying a filename and its own content type.
 */
class Form {
public:
    struct Part {
        std::string name; // the `name` parameter; always present.
        std::string filename; // empty unless this is a file upload.
        std::string contentType; // empty unless the part declared one.
        std::string data;
    };

    Form() = default;

    void add(std::string name, std::string value);
    void addFile(std::string name, std::string filename, std::string data,
        std::string contentType = { });
    void clear() noexcept { parts_.clear(); }

    const std::vector<Part>& parts() const noexcept { return parts_; }
    bool empty() const noexcept { return parts_.empty(); }
    std::size_t size() const noexcept { return parts_.size(); }

    const Part* find(std::string_view name) const;
    std::vector<const Part*> findAll(std::string_view name) const;
    std::vector<std::string> names() const;
    bool has(std::string_view name) const;

    /** First part's data as text, or `std::nullopt`. */
    std::optional<std::string> value(std::string_view name) const;

    /** Serialized body. A random boundary is generated when none is given. */
    std::string encode(std::string_view boundary = { }) const;

    /** `"multipart/form-data; boundary=..."` for the same boundary. */
    std::string contentType(std::string_view boundary = { }) const;

    /** A short, collision-resistant boundary (32 hex chars). */
    static std::string generateBoundary();

    /** Parses a multipart body; throws `FormError` when malformed. */
    static Form decode(std::string_view body, std::string_view boundary);

    /**
     * Dispatches on the media type: `multipart/form-data` and
     * `application/x-www-form-urlencoded` are both understood. Anything else
     * throws `FormError`.
     */
    static Form fromMediaType(const MediaType& mediaType, std::string_view body);

private:
    std::vector<Part> parts_;
};

} // namespace taskpp::http