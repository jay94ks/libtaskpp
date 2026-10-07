// HPACK: static table, integer codec, Huffman decode, encoder/decoder.
#include <taskpp/http/Hpack.hpp>

#include <algorithm>
#include <array>
#include <cstring>

namespace taskpp::http::hpack {
namespace {

// ---------------------------------------------------------- static table

struct StaticEntry {
    const char* name;
    const char* value;
};

// RFC 7541 Appendix A (index = position + 1).
constexpr StaticEntry kStatic[] = {
    { ":authority", "" },
    { ":method", "GET" },
    { ":method", "POST" },
    { ":path", "/" },
    { ":path", "/index.html" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "200" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "304" },
    { ":status", "400" },
    { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" },
};
constexpr size_t kStaticCount = sizeof(kStatic) / sizeof(kStatic[0]); // 61.

// ---------------------------------------------------------- huffman table

#include "HuffmanTable.inc"

// ---------------------------------------------------------- integer codec

struct Cursor {
    const uint8_t* p;
    size_t n;
};

// Reads a prefixed integer (RFC 7541 5.1).
uint32_t readInt(Cursor& c, uint8_t prefixBits) {
    const uint32_t mask = static_cast<uint32_t>((1u << prefixBits) - 1);
    if (c.n < 1) {
        throw HpackError("truncated integer");
    }
    uint32_t value = *c.p++ & mask;
    --c.n;
    if (value < mask) {
        return value;
    }
    uint32_t shift = 0;
    while (true) {
        if (c.n < 1) {
            throw HpackError("truncated integer");
        }
        const uint8_t b = *c.p++;
        --c.n;
        value += static_cast<uint32_t>(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            return value;
        }
        shift += 7;
        if (shift > 28) {
            throw HpackError("integer overflow");
        }
    }
}

void writeInt(std::vector<uint8_t>& out, uint8_t prefixBits, uint8_t prefix, uint32_t value) {
    const uint32_t mask = static_cast<uint32_t>((1u << prefixBits) - 1);
    if (value < mask) {
        out.push_back(static_cast<uint8_t>(prefix | value));
        return;
    }
    out.push_back(static_cast<uint8_t>(prefix | mask));
    value -= mask;
    while (value >= 0x80) {
        out.push_back(static_cast<uint8_t>((value & 0x7F) | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

// ---------------------------------------------------------- huffman decode

std::string huffmanDecode(Cursor& c, size_t length) {
    if (length > c.n) {
        throw HpackError("truncated huffman string");
    }
    const uint8_t* end = c.p + length;
    std::string out;
    uint32_t code = 0;
    uint8_t bits = 0;
    auto emit = [&](uint32_t sym) {
        if (sym == 256) {
            throw HpackError("EOS in huffman string");
        }
        out.push_back(static_cast<char>(sym));
    };
    while (c.p < end) {
        const uint8_t byte = *c.p++;
        --c.n;
        for (int i = 7; i >= 0; --i) {
            code = (code << 1) | ((byte >> i) & 1);
            ++bits;
            bool matched = false;
            for (uint32_t s = 0; s < 257; ++s) {
                if (kHuffman[s].bits == bits && kHuffman[s].code == code) {
                    emit(s);
                    code = 0;
                    bits = 0;
                    matched = true;
                    break;
                }
            }
            if (matched) {
                continue;
            }
            if (bits > 30) {
                throw HpackError("bad huffman code");
            }
            // Possible padding: only allowed at the very end, all ones.
            if (c.p == end && i == 0) {
                // Trailing pad bits must be all ones (RFC 7541 5.2).
                const uint32_t pad = code & ((bits == 32) ? 0xFFFFFFFFu : ((1u << bits) - 1u));
                if (pad != ((bits == 32) ? 0xFFFFFFFFu : ((1u << bits) - 1u))) {
                    throw HpackError("bad huffman padding");
                }
                // A pad longer than 7 bits means a missing symbol.
                if (bits > 7) {
                    // Could still be a valid longer code cut short: only EOS is
                    // 30 bits; anything unfinished here is truncated.
                    throw HpackError("truncated huffman string");
                }
                code = 0;
                bits = 0;
            }
        }
    }
    if (bits != 0) {
        throw HpackError("truncated huffman string");
    }
    return out;
}

std::string readString(Cursor& c) {
    if (c.n < 1) {
        throw HpackError("truncated string");
    }
    const bool huffman = (*c.p & 0x80) != 0;
    const uint32_t length = readInt(c, 7);
    if (huffman) {
        return huffmanDecode(c, length);
    }
    if (length > c.n) {
        throw HpackError("truncated string");
    }
    std::string out(reinterpret_cast<const char*>(c.p), length);
    c.p += length;
    c.n -= length;
    return out;
}

void writeString(std::vector<uint8_t>& out, const std::string& s) {
    // Never Huffman on encode (allowed; keeps frames debuggable).
    writeInt(out, 7, 0x00, static_cast<uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

} // namespace

// ---------------------------------------------------------- decoder

const Decoder::Entry* Decoder::indexed(uint32_t index) const {
    if (index == 0) {
        throw HpackError("index 0");
    }
    if (index <= kStaticCount) {
        static thread_local Entry cache[kStaticCount];
        static thread_local bool ready = false;
        if (!ready) {
            for (size_t i = 0; i < kStaticCount; ++i) {
                cache[i].name = kStatic[i].name;
                cache[i].value = kStatic[i].value;
            }
            ready = true;
        }
        return &cache[index - 1];
    }
    const uint32_t dynamic = index - kStaticCount;
    if (dynamic == 0 || dynamic > dynamic_.size()) {
        throw HpackError("bad dynamic index");
    }
    // Newest first: index 62 is dynamic_[size-1].
    return &dynamic_[dynamic_.size() - dynamic];
}

void Decoder::evictTo(std::size_t maxBytes) {
    while (!dynamic_.empty() && bytes_ > maxBytes) {
        bytes_ -= 32 + dynamic_.front().name.size() + dynamic_.front().value.size();
        dynamic_.erase(dynamic_.begin());
    }
}

void Decoder::insert(HeaderField field) {
    const size_t need = 32 + field.name.size() + field.value.size();
    if (need > maxBytes_) {
        dynamic_.clear();
        bytes_ = 0;
        return;
    }
    evictTo(maxBytes_ - need);
    bytes_ += need;
    dynamic_.push_back({ std::move(field.name), std::move(field.value) });
}

void Decoder::setMaxTableBytes(std::size_t maxBytes) {
    maxBytes_ = maxBytes;
    evictTo(maxBytes_);
}

std::vector<HeaderField> Decoder::decode(const uint8_t* data, size_t n) {
    Cursor c { data, n };
    std::vector<HeaderField> out;
    while (c.n > 0) {
        const uint8_t first = *c.p;
        if (first & 0x80) {
            // Indexed header field (6.1).
            const uint32_t index = readInt(c, 7);
            const Entry* e = indexed(index);
            out.push_back({ e->name, e->value });
        }
        else if (first & 0x40) {
            // Literal with incremental indexing (6.2.1).
            const uint32_t index = readInt(c, 6);
            std::string name;
            if (index == 0) {
                name = readString(c);
            }
            else {
                name = indexed(index)->name;
            }
            std::string value = readString(c);
            out.push_back({ name, value });
            insert({ name, value });
        }
        else if (first & 0x20) {
            // Dynamic table size update (6.3).
            const uint32_t max = readInt(c, 5);
            if (max > maxBytes_) {
                throw HpackError("table size increase");
            }
            evictTo(max);
            maxBytes_ = max;
        }
        else {
            // Literal without indexing (6.2.2) or never-indexed (6.2.3):
            // both surface as plain fields here.
            const uint8_t prefix = static_cast<uint8_t>(first & 0xF0);
            const uint32_t index = readInt(c, 4);
            (void) prefix;
            std::string name;
            if (index == 0) {
                name = readString(c);
            }
            else {
                name = indexed(index)->name;
            }
            out.push_back({ name, readString(c) });
        }
    }
    return out;
}

std::vector<HeaderField> Decoder::decode(const std::vector<uint8_t>& block) {
    return decode(block.data(), block.size());
}

// ---------------------------------------------------------- encoder

std::optional<uint32_t> Encoder::find(const std::string& name, const std::string& value) const {
    for (uint32_t i = 0; i < kStaticCount; ++i) {
        if (name == kStatic[i].name && value == kStatic[i].value) {
            return i + 1;
        }
    }
    for (size_t i = dynamic_.size(); i-- > 0;) {
        if (dynamic_[i].name == name && dynamic_[i].value == value) {
            return static_cast<uint32_t>(kStaticCount + (dynamic_.size() - i));
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> Encoder::findName(const std::string& name) const {
    for (uint32_t i = 0; i < kStaticCount; ++i) {
        if (name == kStatic[i].name) {
            return i + 1;
        }
    }
    for (size_t i = dynamic_.size(); i-- > 0;) {
        if (dynamic_[i].name == name) {
            return static_cast<uint32_t>(kStaticCount + (dynamic_.size() - i));
        }
    }
    return std::nullopt;
}

void Encoder::evictTo(std::size_t maxBytes) {
    while (!dynamic_.empty() && bytes_ > maxBytes) {
        bytes_ -= 32 + dynamic_.front().name.size() + dynamic_.front().value.size();
        dynamic_.erase(dynamic_.begin());
    }
}

void Encoder::insert(Entry entry) {
    const size_t need = 32 + entry.name.size() + entry.value.size();
    if (need > maxBytes_) {
        dynamic_.clear();
        bytes_ = 0;
        return;
    }
    evictTo(maxBytes_ - need);
    bytes_ += need;
    dynamic_.push_back(std::move(entry));
}

void Encoder::setMaxTableBytes(std::size_t maxBytes) {
    maxBytes_ = maxBytes;
    evictTo(maxBytes_);
}

std::vector<uint8_t> Encoder::encode(const std::vector<HeaderField>& fields) {
    std::vector<uint8_t> out;
    for (const auto& f : fields) {
        if (auto full = find(f.name, f.value)) {
            writeInt(out, 7, 0x80, *full);
        }
        else if (auto named = findName(f.name)) {
            writeInt(out, 6, 0x40, *named);
            writeString(out, f.value);
            insert({ f.name, f.value });
        }
        else {
            writeInt(out, 6, 0x40, 0);
            writeString(out, f.name);
            writeString(out, f.value);
            insert({ f.name, f.value });
        }
    }
    return out;
}

} // namespace taskpp::http::hpack
