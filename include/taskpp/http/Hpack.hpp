#pragma once
// HPACK (RFC 7541): header compression for HTTP/2. All names live in
// `taskpp::http::hpack`.
#include <taskpp/Config.hpp>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace taskpp::http::hpack {

struct HeaderField {
    std::string name; // always lowercase on decode.
    std::string value;
};

/** Thrown for malformed header blocks. */
class HpackError : public std::runtime_error {
public:
    explicit HpackError(const std::string& what) : std::runtime_error("hpack: " + what) { }
};

constexpr std::size_t kMaxTableBytes = 4096;

/**
 * Decoder with a dynamic table (max 4096 bytes). `decode()` consumes one full
 * header block (HEADERS/CONTINUATION payload concatenated by the caller).
 */
class Decoder {
public:
    Decoder() = default;

    std::vector<HeaderField> decode(const uint8_t* data, size_t n);
    std::vector<HeaderField> decode(const std::vector<uint8_t>& block);

    /** Peer SETTINGS_HEADER_TABLE_SIZE: evicts down to `maxBytes`. */
    void setMaxTableBytes(std::size_t maxBytes);

private:
    struct Entry {
        std::string name;
        std::string value;
    };

    const Entry* indexed(uint32_t index) const;
    void insert(HeaderField field);
    void evictTo(std::size_t maxBytes);

    std::vector<Entry> dynamic_; // oldest first.
    std::size_t bytes_ = 0;
    std::size_t maxBytes_ = kMaxTableBytes;
};

/**
 * Encoder. Static-table hits become indexed fields, everything else literal
 * with incremental indexing (never Huffman -- allowed, keeps frames debuggable).
 * Names are lowercased; connection-specific headers must be stripped by the
 * caller (H2Connection does it).
 */
class Encoder {
public:
    Encoder() = default;

    std::vector<uint8_t> encode(const std::vector<HeaderField>& fields);

    void setMaxTableBytes(std::size_t maxBytes);

private:
    struct Entry {
        std::string name;
        std::string value;
    };

    std::optional<uint32_t> find(const std::string& name, const std::string& value) const;
    std::optional<uint32_t> findName(const std::string& name) const;
    void insert(Entry entry);
    void evictTo(std::size_t maxBytes);

    std::vector<Entry> dynamic_;
    std::size_t bytes_ = 0;
    std::size_t maxBytes_ = kMaxTableBytes;
};

} // namespace taskpp::http::hpack
