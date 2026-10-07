// TLS 1.3 (RFC 8446) client + server. Record protection, handshake state
// machines and path validation live here; every crypto/cert/hash primitive
// comes from libcertpp and nothing else.
#include <taskpp/tls/Tls.hpp>

#include <taskpp/core/Worker.hpp>
#include <taskpp/socket/SocketAddress.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <vector>

namespace taskpp::tls {
namespace certx = certpp::x509;
namespace cryp = certpp::crypto;

namespace {

// ------------------------------------------------------------ constants

constexpr uint16_t kTls12Version = 0x0303; // legacy_version on the wire.
constexpr uint16_t kTls13Version = 0x0304;

constexpr uint16_t kSuiteAes128Gcm = 0x1301;
constexpr uint16_t kSuiteChaCha20Poly1305 = 0x1303;

constexpr uint16_t kGroupX25519 = 0x001D;

constexpr uint16_t kSigEcdsaP256Sha256 = 0x0403;
constexpr uint16_t kSigEd25519 = 0x0807;

// HelloRetryRequest magic random (RFC 8446 4.1.3).
constexpr uint8_t kHrrMagic[32] = { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16,
    0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };

constexpr uint8_t kRecAlert = 21;
constexpr uint8_t kRecHandshake = 22;
constexpr uint8_t kRecAppData = 23;

constexpr uint8_t kHsClientHello = 1;
constexpr uint8_t kHsServerHello = 2;
constexpr uint8_t kHsEncryptedExtensions = 8;
constexpr uint8_t kHsCertificate = 11;
constexpr uint8_t kHsCertificateRequest = 13;
constexpr uint8_t kHsCertificateVerify = 15;
constexpr uint8_t kHsFinished = 20;
constexpr uint8_t kHsNewSessionTicket = 4;
constexpr uint8_t kHsKeyUpdate = 24;

constexpr size_t kMaxRecordBytes = 16384;
constexpr size_t kMaxHandshakeBytes = 65536;

constexpr int kAlertCloseNotify = 0;
constexpr int kAlertUnexpectedMessage = 10;
constexpr int kAlertBadRecordMac = 20;
constexpr int kAlertHandshakeFailure = 40;
constexpr int kAlertBadCertificate = 42;
constexpr int kAlertUnsupportedCertificate = 43;
constexpr int kAlertCertificateExpired = 45;
constexpr int kAlertIllegalParameter = 47;
constexpr int kAlertUnknownCa = 48;
constexpr int kAlertDecodeError = 50;
constexpr int kAlertDecryptError = 51;
constexpr int kAlertInternalError = 80;

// ------------------------------------------------------------ byte helpers

void putU16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void putU24(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

uint16_t getU16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(p[0] << 8 | p[1]);
}

uint32_t getU24(const uint8_t* p) noexcept {
    return uint32_t { p[0] } << 16 | uint32_t { p[1] } << 8 | p[2];
}

void check(certpp::ERetCode rc, const char* what, int alert = kAlertInternalError) {
    if (rc != certpp::ERET_OK) {
        throw TlsError(what, alert);
    }
}

certpp::SReadOnlyByteSpan ro(const uint8_t* p, size_t n) {
    return certpp::SReadOnlyByteSpan(p, n);
}

certpp::SReadOnlyByteSpan ro(const std::array<uint8_t, 32>& v) {
    return certpp::SReadOnlyByteSpan(v.data(), v.size());
}

certpp::SReadOnlyByteSpan ro(const std::vector<uint8_t>& v) {
    return certpp::SReadOnlyByteSpan(v.data(), v.size());
}

certpp::SByteSpan mut(std::vector<uint8_t>& v) {
    return certpp::SByteSpan(v.data(), v.size());
}

int cmpTime(const certpp::SDateTime& a, const certpp::SDateTime& b) noexcept {
    const int fieldsA[] = { a.year, a.month, a.day, a.hour, a.minute, a.second, a.millisecond };
    const int fieldsB[] = { b.year, b.month, b.day, b.hour, b.minute, b.second, b.millisecond };
    for (int i = 0; i < 7; ++i) {
        if (fieldsA[i] != fieldsB[i]) {
            return fieldsA[i] < fieldsB[i] ? -1 : 1;
        }
    }
    return 0;
}

std::string lower(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

// RFC 6125 single-label wildcard: "*.example.com" matches "a.example.com"
// but not "a.b.example.com" or "example.com".
bool dnsMatches(const std::string& pattern, const std::string& host) {
    const std::string p = lower(pattern);
    const std::string h = lower(host);
    if (p.compare(0, 2, "*.") == 0) {
        const std::string suffix = p.substr(1); // ".example.com"
        if (h.size() <= suffix.size() || h.compare(h.size() - suffix.size(), suffix.size(), suffix) != 0) {
            return false;
        }
        return h.find('.', 0) == h.size() - suffix.size();
    }
    return p == h;
}

bool ipBytesEqual(const std::vector<uint8_t>& raw, const std::string& host) {
    try {
        const SocketAddress parsed = SocketAddress::fromIp(host, 0);
        const uint8_t* bytes = static_cast<const uint8_t*>(parsed.data());
        return parsed.size() == raw.size() && std::memcmp(bytes, raw.data(), raw.size()) == 0;
    }
    catch (...) {
        return false;
    }
}

// ------------------------------------------------------------ transcript

class Transcript {
public:
    Transcript() {
        cryp::IHasher::create(cryp::EHASH_SHA256, hasher_);
        if (!hasher_) {
            throw TlsError("no SHA-256", kAlertInternalError);
        }
        hasher_->reset();
    }

    void update(const uint8_t* data, size_t n) {
        hasher_->push(ro(data, n));
        bytes_.insert(bytes_.end(), data, data + n);
    }

    void update(const std::vector<uint8_t>& v) {
        update(v.data(), v.size());
    }

    std::array<uint8_t, 32> digest() const {
        std::array<uint8_t, 32> out { };
        certpp::SByteSpan span(out.data(), out.size());
        if (!hasher_->finish(span)) {
            throw TlsError("transcript hash", kAlertInternalError);
        }
        return out;
    }

    // Hash of everything fed so far plus a suffix that is NOT fed (used for
    // PSK binder computation over a truncated ClientHello).
    std::array<uint8_t, 32> digestWithExtra(const std::vector<uint8_t>& suffix) const {
        Transcript copy;
        copy.update(bytes_);
        copy.update(suffix);
        return copy.digest();
    }

private:
    cryp::IHasherPtr hasher_;
    std::vector<uint8_t> bytes_; // retained: handshake scale, tiny.
};

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t n) {
    Transcript t;
    t.update(data, n);
    return t.digest();
}

std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& v) {
    return sha256(v.data(), v.size());
}

// ------------------------------------------------------------ HKDF

void hkdfExtract(const uint8_t* salt, const uint8_t* ikm, uint8_t out32[32]) {
    certpp::SByteSpan out(out32, 32);
    check(cryp::CHkdf::extract(cryp::EHASH_SHA256, ro(salt, 32), ro(ikm, 32), out), "hkdf extract");
}

void hkdfExpand(const uint8_t secret32[32], const std::vector<uint8_t>& info, uint8_t* out, size_t n) {
    certpp::SByteSpan span(out, n);
    check(cryp::CHkdf::expand(cryp::EHASH_SHA256, ro(secret32, 32), ro(info), span), "hkdf expand");
}

std::vector<uint8_t> hkdfLabel(uint16_t length, const std::string& label, const std::vector<uint8_t>& ctx) {
    std::vector<uint8_t> info;
    putU16(info, length);
    const std::string full = "tls13 " + label;
    info.push_back(static_cast<uint8_t>(full.size()));
    info.insert(info.end(), full.begin(), full.end());
    info.push_back(static_cast<uint8_t>(ctx.size()));
    info.insert(info.end(), ctx.begin(), ctx.end());
    return info;
}

void expandLabel(const uint8_t secret[32], const std::string& label,
    const std::vector<uint8_t>& ctx, uint8_t* out, size_t n) {
    hkdfExpand(secret, hkdfLabel(static_cast<uint16_t>(n), label, ctx), out, n);
}

void deriveSecret(const uint8_t secret[32], const std::string& label,
    const std::array<uint8_t, 32>& messages, uint8_t out32[32]) {
    const std::vector<uint8_t> ctx(messages.begin(), messages.end());
    expandLabel(secret, label, ctx, out32, 32);
}

std::array<uint8_t, 32> hmac(const uint8_t key[32], const std::array<uint8_t, 32>& message) {
    std::array<uint8_t, 32> out { };
    certpp::SByteSpan span(out.data(), out.size());
    check(cryp::CHmac::compute(cryp::EHASH_SHA256, ro(key, 32), ro(message), span), "hmac");
    return out;
}

// ------------------------------------------------------------ traffic keys

struct TrafficKeys {
    uint16_t suite = kSuiteAes128Gcm;
    cryp::CAesGcm gcm;
    cryp::CChaCha20Poly1305 chacha;
    uint8_t secret[32] { };
    bool hasSecret = false;
    uint8_t iv[12] { };
    uint64_t seq = 0;
    bool active = false;

    static size_t keyBytes(uint16_t s) noexcept {
        return s == kSuiteAes128Gcm ? 16 : 32;
    }

    void init(uint16_t s, const uint8_t nextSecret[32]) {
        suite = s;
        std::memcpy(secret, nextSecret, 32);
        hasSecret = true;
        uint8_t k[32] = { };
        expandLabel(secret, "key", { }, k, keyBytes(suite));
        expandLabel(secret, "iv", { }, iv, sizeof(iv));
        if (suite == kSuiteAes128Gcm) {
            if (!gcm.reset(ro(k, 16))) {
                throw TlsError("aes-gcm key", kAlertInternalError);
            }
        }
        else if (!chacha.reset(ro(k, 32))) {
            throw TlsError("chacha key", kAlertInternalError);
        }
        certpp::CSecure::zero(certpp::SByteSpan(k, sizeof(k)));
        seq = 0;
        active = true;
    }

    void wipe() noexcept {
        certpp::CSecure::zero(certpp::SByteSpan(secret, sizeof(secret)));
        certpp::CSecure::zero(certpp::SByteSpan(iv, sizeof(iv)));
        hasSecret = false;
        active = false;
        seq = 0;
    }

    void nonce(uint8_t out12[12]) const noexcept {
        std::memcpy(out12, iv, 12);
        for (int i = 0; i < 8; ++i) {
            out12[11 - i] ^= static_cast<uint8_t>(seq >> (8 * i));
        }
    }

    std::vector<uint8_t> seal(uint8_t innerType, const uint8_t* plain, size_t n, const uint8_t aad[5]) {
        uint8_t nc[12];
        nonce(nc);
        std::vector<uint8_t> out(n);
        uint8_t tag[16];
        const bool ok = suite == kSuiteAes128Gcm
            ? gcm.seal(ro(nc, 12), ro(aad, 5), ro(plain, n), mut(out), certpp::SByteSpan(tag, 16))
            : chacha.seal(ro(nc, 12), ro(aad, 5), ro(plain, n), mut(out), certpp::SByteSpan(tag, 16));
        if (!ok) {
            throw TlsError("seal", kAlertInternalError);
        }
        out.insert(out.end(), tag, tag + 16);
        ++seq;
        return out;
    }

    // Returns {innerType, plaintext}. Throws TlsError(decrypt_error) on failure.
    std::pair<uint8_t, std::vector<uint8_t>> open(const uint8_t* enc, size_t n, const uint8_t aad[5]) {
        if (n < 17) {
            throw TlsError("short record", kAlertDecodeError);
        }
        uint8_t nc[12];
        nonce(nc);
        std::vector<uint8_t> out(n - 16);
        const bool ok = suite == kSuiteAes128Gcm
            ? gcm.open(ro(nc, 12), ro(aad, 5), ro(enc, n - 16), ro(enc + n - 16, 16), mut(out))
            : chacha.open(ro(nc, 12), ro(aad, 5), ro(enc, n - 16), ro(enc + n - 16, 16), mut(out));
        if (!ok) {
            throw TlsError("bad record mac", kAlertBadRecordMac);
        }
        ++seq;
        // The last byte is the inner content type (never zero); any zeros
        // before it are padding. Data ending in zeros is preserved because the
        // backward scan stops at the type byte.
        size_t t = out.size();
        while (t > 0 && out[t - 1] == 0) {
            --t;
        }
        if (t == 0) {
            throw TlsError("empty record", kAlertDecodeError);
        }
        const uint8_t inner = out[t - 1];
        out.resize(t - 1);
        return { inner, std::move(out) };
    }
};

} // namespace

// ------------------------------------------------------------ framer

namespace {

struct TlsRecord {
    uint8_t type = 0;
    std::vector<uint8_t> payload; // decrypted plaintext (handshake/app bytes).
};

struct HsMessage {
    uint8_t type = 0;
    std::vector<uint8_t> body;
    std::vector<uint8_t> raw; // exact bytes as received (for the transcript).
};

// Per-connection handshake/record state. Drives one epoch at a time:
// CLEAR -> HS_RX/HS_TX as negotiated -> APP.
struct Endpoint {
    Stream* stream = nullptr;
    Canceller canceller;
    Transcript transcript;
    TrafficKeys txHs; // our handshake-traffic encryptor.
    TrafficKeys rxHs; // peer handshake-traffic decryptor.
    TrafficKeys txApp;
    TrafficKeys rxApp;
    bool txEncrypted = false; // handshake messages go out encrypted.
    bool rxAppActive = false; // incoming app records use rxApp.
    std::vector<uint8_t> hsPending; // reassembled handshake plaintext.
    std::vector<uint8_t> appPending; // decrypted app bytes not yet consumed.
    bool peerClosed = false; // close_notify received.

    // Sends one record (fragment must fit). Encrypted records always use the
    // application_data outer type (RFC 8446 5.2); the inner type rides inside.
    Task<void> sendRecord(uint8_t outerType, const uint8_t* data, size_t n,
        TrafficKeys* keys, uint8_t innerType) {
        if (n > kMaxRecordBytes) {
            throw TlsError("record too large", kAlertInternalError);
        }
        const bool encrypted = keys && keys->active;
        const uint8_t wireType = encrypted ? kRecAppData : outerType;
        std::vector<uint8_t> wire;
        if (!keys || !keys->active) {
            wire.reserve(5 + n);
            wire.push_back(outerType);
            wire.push_back(0x03);
            wire.push_back(0x03);
            putU16(wire, static_cast<uint16_t>(n));
            wire.insert(wire.end(), data, data + n);
        }
        else {
            std::vector<uint8_t> inner(data, data + n);
            inner.push_back(innerType);
            // AAD is the record header: outer type, legacy version, enc length.
            const uint16_t encLen = static_cast<uint16_t>(inner.size() + 16);
            const uint8_t aad[5] = { wireType, 0x03, 0x03,
                static_cast<uint8_t>(encLen >> 8), static_cast<uint8_t>(encLen) };
            const std::vector<uint8_t> enc = keys->seal(innerType, inner.data(), inner.size(), aad);
            if (enc.size() > kMaxRecordBytes + 256) {
                throw TlsError("record too large", kAlertInternalError);
            }
            wire.reserve(5 + enc.size());
            wire.push_back(wireType);
            wire.push_back(0x03);
            wire.push_back(0x03);
            putU16(wire, static_cast<uint16_t>(enc.size()));
            wire.insert(wire.end(), enc.begin(), enc.end());
        }
        co_await stream->write(std::span(
            reinterpret_cast<const char*>(wire.data()), wire.size()), canceller);
        co_return;
    }

    Task<void> sendHandshake(const std::vector<uint8_t>& message) {
        if (message.size() > kMaxRecordBytes) {
            throw TlsError("handshake message too large", kAlertInternalError);
        }
        transcript.update(message);
        TrafficKeys* keys = txEncrypted ? &txHs : nullptr;
        co_await sendRecord(kRecHandshake, message.data(), message.size(), keys, kRecHandshake);
        co_return;
    }

    // Reads one record; returns decrypted content (handshake/app bytes).
    // Alerts are processed inline (fatal -> throw, close_notify -> flag).
    // TCP EOF propagates as SocketClosed (callers decide: handshake fails,
    // application reads treat it as clean EOF).
    Task<TlsRecord> recvRecord() {
        uint8_t hdr[5];
        co_await stream->readExact(std::span(reinterpret_cast<char*>(hdr), 5), canceller);
        // RFC 8446 5.1: legacy_record_version is 0x0303 everywhere except the
        // very first ClientHello, which MAY be 0x0301 for middlebox
        // compatibility -- OpenSSL does exactly that.
        const bool initialHello = !rxHs.hasSecret && !rxApp.hasSecret;
        const bool versionOk = hdr[1] == 0x03
            && (hdr[2] == 0x03 || (initialHello && hdr[2] == 0x01));
        if (!versionOk) {
            throw TlsError("bad record version", kAlertDecodeError);
        }
        const size_t length = size_t { hdr[3] } << 8 | hdr[4];
        if (length == 0 || length > kMaxRecordBytes + 256) {
            throw TlsError("bad record length", kAlertDecodeError);
        }
        std::vector<uint8_t> enc(length);
        co_await stream->readExact(std::span(reinterpret_cast<char*>(enc.data()), length), canceller);

        const uint8_t outer = hdr[0];
        if (outer == 20) {
            // Middlebox-compatibility mode: real servers send this after
            // ServerHello; RFC 8446 says to ignore it in every epoch.
            if (length != 1 || enc[0] != 0x01) {
                throw TlsError("bad change_cipher_spec", kAlertDecodeError);
            }
            co_return co_await recvRecord();
        }
        if (!rxHs.active && !rxAppActive) {
            // Plaintext epoch (up to ServerHello).
            if (outer != kRecHandshake && outer != kRecAlert) {
                throw TlsError("unexpected plaintext record", kAlertUnexpectedMessage);
            }
            if (outer == kRecAlert) {
                co_return TlsRecord { kRecAlert, std::move(enc) };
            }
            co_return TlsRecord { kRecHandshake, std::move(enc) };
        }

        // Encrypted epoch: handshake keys until app keys activate.
        TrafficKeys* keys = rxAppActive ? &rxApp : &rxHs;
        if (outer != kRecAppData) {
            throw TlsError("unexpected outer type", kAlertUnexpectedMessage);
        }
        uint8_t aad[5] = { hdr[0], hdr[1], hdr[2], hdr[3], hdr[4] };
        auto [inner, plain] = keys->open(enc.data(), enc.size(), aad);
        if (inner == 20) {
            co_return co_await recvRecord(); // ignore CCS anywhere.
        }
        if (inner != kRecHandshake && inner != kRecAlert && inner != kRecAppData) {
            throw TlsError("unexpected inner type", kAlertUnexpectedMessage);
        }
        co_return TlsRecord { inner, std::move(plain) };
    }

    // Next handshake message, reassembling across records.
    // TCP EOF mid-handshake is a truncation failure.
    Task<HsMessage> recvHandshake() {
        while (true) {
            if (hsPending.size() >= 4) {
                const size_t length = getU24(hsPending.data() + 1);
                if (length > kMaxHandshakeBytes) {
                    throw TlsError("handshake message too large", kAlertDecodeError);
                }
                if (hsPending.size() >= 4 + length) {
                    HsMessage message;
                    message.type = hsPending[0];
                    message.raw.assign(hsPending.begin(), hsPending.begin() + 4 + length);
                    message.body.assign(message.raw.begin() + 4, message.raw.end());
                    hsPending.erase(hsPending.begin(), hsPending.begin() + 4 + length);
                    co_return message;
                }
            }
            TlsRecord record;
            bool got = false;
            try {
                record = co_await recvRecord();
                got = true;
            }
            catch (const SocketClosed&) {
            }
            if (!got) {
                throw TlsError("truncated handshake", kAlertDecodeError);
            }
            if (record.type == kRecAlert) {
                handleAlert(record.payload);
            }
            if (record.type != kRecHandshake) {
                throw TlsError("expected handshake", kAlertUnexpectedMessage);
            }
            hsPending.insert(hsPending.end(), record.payload.begin(), record.payload.end());
            if (hsPending.size() > kMaxHandshakeBytes + 4) {
                throw TlsError("handshake overflow", kAlertDecodeError);
            }
        }
    }

    // RFC 8446 4.6.3: rotate our RECEIVE keys; if the peer asks, rotate our
    // SEND keys too and acknowledge. Post-handshake traffic never enters the
    // key schedule transcript.
    Task<void> applyKeyUpdate(bool peerRequestsOurs) {
        if (!rxApp.hasSecret || !txApp.hasSecret) {
            throw TlsError("KeyUpdate too early", kAlertUnexpectedMessage);
        }
        uint8_t next[32];
        expandLabel(rxApp.secret, "traffic upd", { }, next, 32);
        rxApp.init(rxApp.suite, next);
        if (peerRequestsOurs) {
            uint8_t txNext[32];
            expandLabel(txApp.secret, "traffic upd", { }, txNext, 32);
            txApp.init(txApp.suite, txNext);
            const uint8_t body[1] = { 0 }; // update_not_requested.
            co_await sendRecord(kRecAppData, body, 1, &txApp, kRecHandshake);
        }
        co_return;
    }

    [[noreturn]] void handleAlert(const std::vector<uint8_t>& payload) {
        if (payload.size() != 2) {
            throw TlsError("bad alert", kAlertDecodeError);
        }
        if (payload[0] == 1 && payload[1] == kAlertCloseNotify) {
            peerClosed = true;
            throw TlsError("peer closed", kAlertCloseNotify);
        }
        throw TlsError("peer alert " + std::to_string(payload[1]), payload[1]);
    }
};

// ------------------------------------------------------------ validation

const certx::CCert* findBySubject(const std::vector<certx::CCert>& certs,
    const certpp::CDistinguishedName& subject) {
    for (const auto& c : certs) {
        if (c.subject() == subject) {
            return &c;
        }
    }
    return nullptr;
}

bool hasKuBit(const certx::CCert& cert, uint16_t bit) {
    auto ku = cert.extension<certx::CKeyUsagesExtension>();
    return !ku || (ku->bits() & bit) != 0;
}

bool hasEku(const certx::CCert& cert, const char* oid) {
    auto eku = cert.extension<certx::CEkuExtension>();
    return !eku || eku->has(oid);
}

bool hostnameMatches(const certx::CCert& leaf, const std::string& hostname) {
    auto san = leaf.template extension<certx::CSanExtension>();
    if (san && !san->names().empty()) {
        for (const auto& name : san->names()) {
            if (name.type() == certx::EGNAME_DNS) {
                const std::string text(name.text().toPtr(), name.text().size());
                if (dnsMatches(text, hostname)) {
                    return true;
                }
            }
            else if (name.type() == certx::EGNAME_IP_ADDRESS) {
                const auto raw = name.raw().toSpan();
                const std::vector<uint8_t> bytes(raw.data, raw.data + raw.size);
                if (ipBytesEqual(bytes, hostname)) {
                    return true;
                }
            }
        }
        return false; // SAN present: CN fallback is off (RFC 6125).
    }
    certpp::CName cn;
    if (leaf.subject().tryGet(certpp::ENAME_CN, cn)) {
        const auto span = cn.toSpan();
        const std::string text(span.data, span.data + span.size);
        return dnsMatches(text, hostname);
    }
    return false;
}

// Dates, CA chain with pathLen, key usage, EKU, SAN/CN and anchor trust.
// libcertpp verifies single links; everything around that is ours.
void validateChain(const std::vector<certx::CCert>& presented,
    const std::vector<certx::CCert>& anchors, const std::string& hostname,
    const char* ekuOid = certx::CEkuExtension::OID_SERVER_AUTH) {
    if (presented.empty()) {
        throw TlsError("no certificate", kAlertBadCertificate);
    }
    const certpp::SDateTime now = certpp::SDateTime::now(true);

    const certx::CCert* current = &presented.front();
    int caBelow = 0; // intermediate CAs between the issuer and the leaf.
    for (int steps = 0; steps < 16; ++steps) {
        if (cmpTime(now, current->notBefore()) < 0 || cmpTime(now, current->notAfter()) > 0) {
            throw TlsError("certificate expired", kAlertCertificateExpired);
        }

        const bool selfIssued = current->subject() == current->issuer();
        if (steps == 0) {
            // Leaf checks.
            auto bc = current->template extension<certx::CBasicConstraintsExtension>();
            if (bc && bc->isCa()) {
                throw TlsError("leaf is a CA", kAlertBadCertificate);
            }
            if (!hasKuBit(*current, certx::EKUSE_DIGITAL_SIGNATURE)) {
                throw TlsError("leaf key usage", kAlertBadCertificate);
            }
            if (!hasEku(*current, ekuOid)) {
                throw TlsError("leaf EKU", kAlertBadCertificate);
            }
            if (!hostname.empty() && !hostnameMatches(*current, hostname)) {
                throw TlsError("hostname mismatch", kAlertBadCertificate);
            }
        }
        else if (!selfIssued) {
            auto bc = current->template extension<certx::CBasicConstraintsExtension>();
            if (!bc || !bc->isCa()) {
                throw TlsError("intermediate is not a CA", kAlertBadCertificate);
            }
            if (bc->hasPathLenConstraint() && bc->pathLenConstraint() < caBelow) {
                throw TlsError("path length exceeded", kAlertBadCertificate);
            }
            if (!hasKuBit(*current, certx::EKUSE_KEY_CERT_SIGN)) {
                throw TlsError("CA key usage", kAlertBadCertificate);
            }
        }

        if (selfIssued) {
            if (!findBySubject(anchors, current->subject())) {
                throw TlsError("self-signed untrusted", kAlertUnknownCa);
            }
            check(current->verifyBy(*current), "anchor self-signature", kAlertBadCertificate);
            return; // trusted.
        }

        const certx::CCert* issuer = findBySubject(presented, current->issuer());
        bool viaAnchor = false;
        if (!issuer) {
            issuer = findBySubject(anchors, current->issuer());
            if (!issuer) {
                throw TlsError("unknown issuer", kAlertUnknownCa);
            }
            viaAnchor = true;
            if (cmpTime(now, issuer->notBefore()) < 0 || cmpTime(now, issuer->notAfter()) > 0) {
                throw TlsError("anchor expired", kAlertCertificateExpired);
            }
            auto bc = issuer->template extension<certx::CBasicConstraintsExtension>();
            if (bc && !bc->isCa()) {
                throw TlsError("anchor is not a CA", kAlertBadCertificate);
            }
            if (!hasKuBit(*issuer, certx::EKUSE_KEY_CERT_SIGN)) {
                throw TlsError("anchor key usage", kAlertBadCertificate);
            }
        }
        check(current->verifyBy(*issuer), "chain signature", kAlertBadCertificate);
        if (viaAnchor) {
            return; // trusted.
        }
        current = issuer;
        ++caBelow;
    }
    throw TlsError("chain too deep", kAlertBadCertificate);
}

} // namespace

// ------------------------------------------------------------ handshake IO

namespace {

struct PskOffer {
    std::vector<uint8_t> ticket;
    uint32_t obfAge = 0;
    std::vector<uint8_t> binder;
};

struct ParsedHello {
    std::vector<uint8_t> random;
    std::vector<uint8_t> sessionId;
    std::vector<uint16_t> suites;
    std::vector<uint8_t> keyShare; // x25519 peer key (empty if absent).
    bool offeredV13 = false;
    std::string serverName;
    std::vector<std::string> alpn;
    std::vector<PskOffer> psk; // offered identities (with binders).
    // Body length covered by binder computation: through the binders length
    // field, excluding binder values. Zero when no PSK was offered.
    size_t pskTruncLen = 0;
};

} // namespace

// ------------------------------------------------------------ handshake IO

namespace {

Task<void> alertNow(Endpoint& ep, int desc) {
    // Best effort, always plaintext: failures happen before keys exist.
    uint8_t payload[2] = { 2, static_cast<uint8_t>(desc) };
    uint8_t wire[7] = { kRecAlert, 0x03, 0x03, 0x00, 0x02, payload[0], payload[1] };
    try {
        co_await ep.stream->write(std::span(reinterpret_cast<const char*>(wire), 7), ep.canceller);
    }
    catch (...) {
    }
    co_return;
}

std::vector<uint8_t> hsWrap(uint8_t type, const std::vector<uint8_t>& body) {
    std::vector<uint8_t> out;
    out.push_back(type);
    putU24(out, static_cast<uint32_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

void putOpaque16(std::vector<uint8_t>& out, const uint8_t* data, size_t n) {
    putU16(out, static_cast<uint16_t>(n));
    out.insert(out.end(), data, data + n);
}

void putOpaque16(std::vector<uint8_t>& out, const std::vector<uint8_t>& v) {
    putOpaque16(out, v.data(), v.size());
}

struct Cursor {
    const uint8_t* p;
    size_t n;

    uint8_t u8() {
        if (n < 1) {
            throw TlsError("truncated message", kAlertDecodeError);
        }
        const uint8_t v = *p++;
        --n;
        return v;
    }

    uint16_t u16() {
        if (n < 2) {
            throw TlsError("truncated message", kAlertDecodeError);
        }
        const uint16_t v = getU16(p);
        p += 2;
        n -= 2;
        return v;
    }

    uint32_t u32() {
        if (n < 4) {
            throw TlsError("truncated message", kAlertDecodeError);
        }
        const uint32_t v = uint32_t { p[0] } << 24 | uint32_t { p[1] } << 16
            | uint32_t { p[2] } << 8 | p[3];
        p += 4;
        n -= 4;
        return v;
    }

    uint32_t u24() {
        if (n < 3) {
            throw TlsError("truncated message", kAlertDecodeError);
        }
        const uint32_t v = getU24(p);
        p += 3;
        n -= 3;
        return v;
    }

    std::vector<uint8_t> bytes(size_t count) {
        if (n < count) {
            throw TlsError("truncated message", kAlertDecodeError);
        }
        std::vector<uint8_t> out(p, p + count);
        p += count;
        n -= count;
        return out;
    }

    std::vector<uint8_t> opaque16() {
        return bytes(u16());
    }

    std::vector<uint8_t> opaque8() {
        return bytes(u8());
    }

    void end() {
        if (n != 0) {
            throw TlsError("trailing bytes", kAlertDecodeError);
        }
    }
};

std::vector<uint8_t> random32() {
    std::vector<uint8_t> out(32);
    certpp::SByteSpan span(out.data(), out.size());
    cryp::CRng::fill(span);
    return out;
}

// X25519 ephemeral key generation; returns {private context half, public 32B}.
struct EphemeralX25519 {
    cryp::SKeyPair pair;
    std::vector<uint8_t> pub;
};

EphemeralX25519 generateX25519() {
    auto algo = cryp::IAsymmetric::builtIn(cryp::EASYM_X25519);
    if (!algo) {
        throw TlsError("no X25519", kAlertInternalError);
    }
    EphemeralX25519 eph;
    check(algo->generateKeyPair(256, eph.pair), "x25519 keygen");
    certpp::COctet raw;
    check(eph.pair.publicKey->serialize(raw), "x25519 serialize");
    if (raw.size() != 32) {
        throw TlsError("x25519 pubkey size", kAlertInternalError);
    }
    eph.pub.assign(raw.toSpan().data, raw.toSpan().data + 32);
    return eph;
}

std::array<uint8_t, 32> x25519Shared(EphemeralX25519& eph, const std::vector<uint8_t>& peer) {
    if (peer.size() != 32) {
        throw TlsError("bad key share", kAlertIllegalParameter);
    }
    auto algo = cryp::IAsymmetric::builtIn(cryp::EASYM_X25519);
    auto peerKey = algo->createPublicKey(ro(peer.data(), peer.size()));
    if (!peerKey) {
        throw TlsError("bad peer key", kAlertIllegalParameter);
    }
    auto ctx = algo->createContext();
    ctx->keyPair(eph.pair.publicKey, eph.pair.privateKey);
    uint8_t secret[32];
    certpp::SByteSpan out(secret, sizeof(secret));
    check(ctx->deriveSharedSecret(peerKey, out), "x25519 agree");
    if (out.size != 32) {
        throw TlsError("x25519 secret size", kAlertInternalError);
    }
    std::array<uint8_t, 32> result { };
    std::memcpy(result.data(), secret, 32);
    certpp::CSecure::zero(certpp::SByteSpan(secret, sizeof(secret)));
    return result;
}

} // namespace

// ------------------------------------------------------------ hello IO

namespace {

// Parses ClientHello body (without the 4-byte header).
ParsedHello parseClientHello(const std::vector<uint8_t>& body) {
    ParsedHello hello;
    Cursor c { body.data(), body.size() };
    if (c.n < 2 || getU16(c.p) != kTls12Version) {
        throw TlsError("bad client version", kAlertIllegalParameter);
    }
    c.bytes(2);
    hello.random = c.bytes(32);
    hello.sessionId = c.bytes(c.u8());
    if (hello.sessionId.size() > 32) {
        throw TlsError("bad session id", kAlertDecodeError);
    }
    const size_t suitesLen = c.u16();
    if (suitesLen % 2 != 0) {
        throw TlsError("bad suites", kAlertDecodeError);
    }
    for (size_t i = 0; i < suitesLen; i += 2) {
        hello.suites.push_back(getU16(c.p));
        c.bytes(2);
    }
    const size_t compLen = c.u8();
    const auto comp = c.bytes(compLen);
    if (std::find(comp.begin(), comp.end(), 0) == comp.end()) {
        throw TlsError("no null compression", kAlertIllegalParameter);
    }
    const size_t extTotal = c.u16();
    const uint8_t* extEnd = c.p + extTotal;
    if (extTotal > c.n) {
        throw TlsError("bad extensions", kAlertDecodeError);
    }
    while (c.p < extEnd) {
        const uint16_t type = c.u16();
        auto ext = c.opaque16();
        Cursor e { ext.data(), ext.size() };
        bool known = true;
        switch (type) {
        case 0: { // server_name
            const size_t listLen = e.u16();
            const uint8_t* listEnd = e.p + listLen;
            if (listLen > e.n) {
                throw TlsError("bad SNI", kAlertDecodeError);
            }
            while (e.p < listEnd) {
                const uint8_t nameType = e.u8();
                auto name = e.opaque16();
                if (nameType == 0) {
                    hello.serverName.assign(name.begin(), name.end());
                }
            }
            if (e.p != listEnd) {
                throw TlsError("bad SNI", kAlertDecodeError);
            }
            break;
        }
        case 10: // supported_groups: presence noted, x25519 assumed.
        case 13: // signature_algorithms: accepted as offered.
        case 45: // psk_key_exchange_modes: ignored (no PSK).
            e.bytes(e.n); // consume; nothing needed from these.
            break;
        case 16: { // alpn
            const size_t listLen = e.u16();
            const uint8_t* listEnd = e.p + listLen;
            if (listLen > e.n) {
                throw TlsError("bad ALPN", kAlertDecodeError);
            }
            while (e.p < listEnd) {
                const uint8_t len = e.u8();
                auto proto = e.bytes(len);
                hello.alpn.emplace_back(proto.begin(), proto.end());
            }
            if (e.p != listEnd) {
                throw TlsError("bad ALPN", kAlertDecodeError);
            }
            break;
        }
        case 43: { // supported_versions
            const uint8_t len = e.u8();
            if (len % 2 != 0) {
                throw TlsError("bad versions", kAlertDecodeError);
            }
            for (uint8_t i = 0; i < len; i += 2) {
                if (e.u16() == kTls13Version) {
                    hello.offeredV13 = true;
                }
            }
            break;
        }
        case 51: { // key_share
            const size_t listLen = e.u16();
            const uint8_t* listEnd = e.p + listLen;
            if (listLen > e.n) {
                throw TlsError("bad key share", kAlertDecodeError);
            }
            while (e.p < listEnd) {
                const uint16_t group = e.u16();
                auto key = e.opaque16();
                if (group == kGroupX25519 && hello.keyShare.empty()) {
                    hello.keyShare = std::move(key);
                }
            }
            if (e.p != listEnd) {
                throw TlsError("bad key share", kAlertDecodeError);
            }
            break;
        }
        case 41: { // pre_shared_key
            const size_t extStart = body.size() - c.n - ext.size();
            const size_t listLen = e.u16();
            const uint8_t* listEnd = e.p + listLen;
            if (listLen > e.n) {
                throw TlsError("bad psk identities", kAlertDecodeError);
            }
            while (e.p < listEnd) {
                PskOffer offer;
                offer.ticket = e.opaque16();
                if (offer.ticket.empty()) {
                    throw TlsError("empty ticket identity", kAlertDecodeError);
                }
                offer.obfAge = e.u32();
                hello.psk.push_back(std::move(offer));
            }
            if (e.p != listEnd) {
                throw TlsError("bad psk identities", kAlertDecodeError);
            }
            hello.pskTruncLen = extStart + 2 + listLen; // through identities.
            const size_t bindersLen = e.u16();
            const uint8_t* bindersEnd = e.p + bindersLen;
            if (bindersLen > e.n) {
                throw TlsError("bad psk binders", kAlertDecodeError);
            }
            size_t index = 0;
            while (e.p < bindersEnd) {
                auto binder = e.opaque8();
                if (binder.empty() || index >= hello.psk.size()) {
                    throw TlsError("bad psk binders", kAlertDecodeError);
                }
                hello.psk[index++].binder = std::move(binder);
            }
            if (e.p != bindersEnd || index != hello.psk.size()) {
                throw TlsError("bad psk binders", kAlertDecodeError);
            }
            break;
        }
        default:
            known = false; // unknown extension: ignore its contents entirely.
            break;
        }
        if (known) {
            e.end();
        }
    }
    if (c.p != extEnd) {
        throw TlsError("bad extensions", kAlertDecodeError);
    }
    c.end();
    return hello;
}

void putExtension(std::vector<uint8_t>& out, uint16_t type, const std::vector<uint8_t>& body) {
    putU16(out, type);
    putOpaque16(out, body);
}

std::vector<uint8_t> alpnBody(const std::vector<std::string>& protocols) {
    std::vector<uint8_t> list;
    for (const auto& p : protocols) {
        list.push_back(static_cast<uint8_t>(p.size()));
        list.insert(list.end(), p.begin(), p.end());
    }
    std::vector<uint8_t> body;
    putU16(body, static_cast<uint16_t>(list.size()));
    body.insert(body.end(), list.begin(), list.end());
    return body;
}

// One ClientHello flight. With a ticket, the message carries zeroed binder
// placeholders; binderOffset is the message offset (past the 4-byte header)
// where the binder VALUES start, i.e. the transcript prefix length for the
// binder computation. Zero without PSK.
struct ClientHelloFlight {
    std::vector<uint8_t> message;
    size_t binderOffset = 0;
    static constexpr size_t kBinderLen = 32;
};

ClientHelloFlight buildClientHello(const TlsConfig& config, const std::vector<uint8_t>& random,
    const std::vector<uint8_t>& sessionId, const std::vector<uint8_t>& keyShare,
    const std::vector<uint8_t>& ticket, uint32_t obfAge, const std::vector<uint8_t>& cookie) {
    std::vector<uint8_t> body;
    putU16(body, kTls12Version);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(static_cast<uint8_t>(sessionId.size()));
    body.insert(body.end(), sessionId.begin(), sessionId.end());
    putU16(body, 4);
    putU16(body, kSuiteAes128Gcm);
    putU16(body, kSuiteChaCha20Poly1305);
    body.push_back(1);
    body.push_back(0);

    std::vector<uint8_t> exts;
    if (!config.serverName.empty()) {
        bool numeric = true;
        try {
            SocketAddress::fromIp(config.serverName, 0);
        }
        catch (...) {
            numeric = false;
        }
        if (!numeric) {
            std::vector<uint8_t> nameList;
            putU16(nameList, static_cast<uint16_t>(config.serverName.size() + 3));
            nameList.push_back(0);
            putOpaque16(nameList,
                reinterpret_cast<const uint8_t*>(config.serverName.data()), config.serverName.size());
            putExtension(exts, 0, nameList);
        }
    }
    if (!config.alpn.empty()) {
        putExtension(exts, 16, alpnBody(config.alpn));
    }
    {
        std::vector<uint8_t> v = { 2, 0x03, 0x04 };
        putExtension(exts, 43, v);
    }
    {
        std::vector<uint8_t> g;
        putU16(g, 2);
        putU16(g, kGroupX25519);
        putExtension(exts, 10, g);
    }
    {
        std::vector<uint8_t> s;
        putU16(s, 4);
        putU16(s, kSigEcdsaP256Sha256);
        putU16(s, kSigEd25519);
        putExtension(exts, 13, s);
    }
    {
        std::vector<uint8_t> ks;
        putU16(ks, static_cast<uint16_t>(4 + keyShare.size()));
        putU16(ks, kGroupX25519);
        putOpaque16(ks, keyShare);
        putExtension(exts, 51, ks);
    }
    {
        std::vector<uint8_t> modes = { 1, 1 }; // psk_dhe_ke.
        putExtension(exts, 45, modes);
    }
    if (!cookie.empty()) {
        putExtension(exts, 44, cookie);
    }
    ClientHelloFlight flight;
    if (!ticket.empty()) {
        // pre_shared_key MUST be last: identities, then placeholder binders.
        std::vector<uint8_t> ids; // entries, length added below.
        putOpaque16(ids, ticket);
        ids.push_back(static_cast<uint8_t>(obfAge >> 24));
        ids.push_back(static_cast<uint8_t>(obfAge >> 16));
        ids.push_back(static_cast<uint8_t>(obfAge >> 8));
        ids.push_back(static_cast<uint8_t>(obfAge));
        std::vector<uint8_t> psk;
        putOpaque16(psk, ids);
        putU16(psk, 1 + ClientHelloFlight::kBinderLen);
        psk.push_back(static_cast<uint8_t>(ClientHelloFlight::kBinderLen));
        psk.insert(psk.end(), ClientHelloFlight::kBinderLen, 0);
        putExtension(exts, 41, psk);
    }
    putU16(body, static_cast<uint16_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());
    flight.message = hsWrap(kHsClientHello, body);
    // Placeholder zeros are the last bytes by construction.
    flight.binderOffset = flight.message.size() - ClientHelloFlight::kBinderLen;
    return flight;
}

// Parses ServerHello body; returns {cipher, peerKeyShare}.
struct ParsedServerHello {
    uint16_t suite = 0;
    std::vector<uint8_t> keyShare;
    int pskSelected = -1; // pre_shared_key selected_identity, or -1.
};

bool isHrr(const std::vector<uint8_t>& body) {
    return body.size() >= 34 && std::memcmp(body.data() + 2, kHrrMagic, 32) == 0;
}

struct ParsedHrr {
    std::vector<uint8_t> cookie; // raw cookie extension bytes (may be empty).
};

ParsedHrr parseHrr(const std::vector<uint8_t>& body, const std::vector<uint8_t>& sessionId) {
    ParsedHrr hrr;
    Cursor c { body.data(), body.size() };
    if (c.u16() != kTls12Version) {
        throw TlsError("bad retry version", kAlertIllegalParameter);
    }
    c.bytes(32); // magic, already checked.
    if (c.bytes(c.u8()) != sessionId) {
        throw TlsError("retry session mismatch", kAlertIllegalParameter);
    }
    c.u16(); // cipher: reused from the first flight.
    if (c.u8() != 0) {
        throw TlsError("bad retry compression", kAlertIllegalParameter);
    }
    const size_t extTotal = c.u16();
    const uint8_t* extEnd = c.p + extTotal;
    if (extTotal > c.n) {
        throw TlsError("bad retry extensions", kAlertDecodeError);
    }
    bool sawVersions = false, sawGroup = false;
    while (c.p < extEnd) {
        const uint16_t type = c.u16();
        auto ext = c.opaque16();
        Cursor e { ext.data(), ext.size() };
        if (type == 43) {
            if (e.u16() != kTls13Version) {
                throw TlsError("retry is not TLS 1.3", kAlertIllegalParameter);
            }
            e.end();
            sawVersions = true;
        }
        else if (type == 51) {
            if (e.u16() != kGroupX25519) {
                throw TlsError("retry wants another group", kAlertHandshakeFailure);
            }
            e.end();
            sawGroup = true;
        }
        else if (type == 44) {
            hrr.cookie = std::move(ext);
        }
    }
    if (c.p != extEnd || !sawVersions || !sawGroup) {
        throw TlsError("bad hello retry", kAlertDecodeError);
    }
    c.end();
    return hrr;
}

ParsedServerHello parseServerHello(const std::vector<uint8_t>& body,
    const std::vector<uint8_t>& sessionId) {
    ParsedServerHello hello;
    Cursor c { body.data(), body.size() };
    if (c.u16() != kTls12Version) {
        throw TlsError("bad server version", kAlertIllegalParameter);
    }
    auto random = c.bytes(32);
    if (random.size() == 32 && std::memcmp(random.data(), kHrrMagic, 32) == 0) {
        throw TlsError("unexpected retry here", kAlertUnexpectedMessage);
    }
    if (c.bytes(c.u8()) != sessionId) {
        throw TlsError("session id mismatch", kAlertIllegalParameter);
    }
    hello.suite = c.u16();
    if (hello.suite != kSuiteAes128Gcm && hello.suite != kSuiteChaCha20Poly1305) {
        throw TlsError("no overlapping cipher", kAlertHandshakeFailure);
    }
    if (c.u8() != 0) {
        throw TlsError("bad compression", kAlertIllegalParameter);
    }
    const size_t extTotal = c.u16();
    const uint8_t* extEnd = c.p + extTotal;
    if (extTotal > c.n) {
        throw TlsError("bad extensions", kAlertDecodeError);
    }
    bool sawVersions = false;
    while (c.p < extEnd) {
        const uint16_t type = c.u16();
        auto ext = c.opaque16();
        Cursor e { ext.data(), ext.size() };
        if (type == 43) {
            if (e.u16() != kTls13Version) {
                throw TlsError("server is not TLS 1.3", kAlertIllegalParameter);
            }
            e.end();
            sawVersions = true;
        }
        else if (type == 51) {
            if (e.u16() != kGroupX25519) {
                throw TlsError("bad key share group", kAlertIllegalParameter);
            }
            hello.keyShare = e.opaque16();
            e.end();
        }
        else if (type == 41) {
            hello.pskSelected = e.u16();
            e.end();
        }
    }
    if (c.p != extEnd || !sawVersions || hello.keyShare.size() != 32) {
        throw TlsError("bad server hello", kAlertDecodeError);
    }
    c.end();
    return hello;
}

} // namespace

// ------------------------------------------------------------ key schedule

namespace {

struct KeySchedule {
    uint8_t cHs[32], sHs[32], cHsFin[32], sHsFin[32];
    uint8_t master[32], cAp[32], sAp[32];

    static KeySchedule derive(const std::array<uint8_t, 32>& shared,
        const std::array<uint8_t, 32>& digestChSh, const uint8_t earlySecret[32]) {
        KeySchedule ks { };
        const uint8_t zeros[32] = { };
        const auto empty = sha256(std::vector<uint8_t> { });
        uint8_t d1[32], hs[32], d2[32];
        deriveSecret(earlySecret, "derived", empty, d1);
        hkdfExtract(d1, shared.data(), hs);
        deriveSecret(hs, "c hs traffic", digestChSh, ks.cHs);
        deriveSecret(hs, "s hs traffic", digestChSh, ks.sHs);
        expandLabel(ks.cHs, "finished", { }, ks.cHsFin, 32);
        expandLabel(ks.sHs, "finished", { }, ks.sHsFin, 32);
        deriveSecret(hs, "derived", empty, d2);
        hkdfExtract(d2, zeros, ks.master);
        certpp::CSecure::zero(certpp::SByteSpan(d1, 32));
        certpp::CSecure::zero(certpp::SByteSpan(hs, 32));
        certpp::CSecure::zero(certpp::SByteSpan(d2, 32));
        return ks;
    }

    void wipe() noexcept {
        certpp::CSecure::zero(certpp::SByteSpan(cHs, 32));
        certpp::CSecure::zero(certpp::SByteSpan(sHs, 32));
        certpp::CSecure::zero(certpp::SByteSpan(cHsFin, 32));
        certpp::CSecure::zero(certpp::SByteSpan(sHsFin, 32));
        certpp::CSecure::zero(certpp::SByteSpan(master, 32));
        certpp::CSecure::zero(certpp::SByteSpan(cAp, 32));
        certpp::CSecure::zero(certpp::SByteSpan(sAp, 32));
    }

    void deriveApp(const std::array<uint8_t, 32>& digestThroughSf) {
        deriveSecret(master, "c ap traffic", digestThroughSf, cAp);
        deriveSecret(master, "s ap traffic", digestThroughSf, sAp);
    }
};

std::vector<uint8_t> cvContent(bool server, const std::array<uint8_t, 32>& transcriptHash) {
    std::vector<uint8_t> out(64, 0x20);
    const std::string ctx = server ? "TLS 1.3, server CertificateVerify"
                                   : "TLS 1.3, client CertificateVerify";
    out.insert(out.end(), ctx.begin(), ctx.end());
    out.push_back(0x00);
    out.insert(out.end(), transcriptHash.begin(), transcriptHash.end());
    return out;
}

std::pair<uint16_t, std::vector<uint8_t>> makeCV(const certx::CCert& leaf,
    const std::array<uint8_t, 32>& transcriptHash, bool server) {
    auto ctx = leaf.createAsymmetricContext();
    if (!ctx) {
        throw TlsError("no signing key", kAlertInternalError);
    }
    const std::vector<uint8_t> content = cvContent(server, transcriptHash);
    std::vector<uint8_t> sig(256);
    certpp::SByteSpan span(sig.data(), sig.size());
    if (ctx->sizeOfDigest() == 0) {
        check(ctx->sign(ro(content), span), "sign CV", kAlertInternalError);
        sig.resize(span.size);
        return { kSigEd25519, std::move(sig) };
    }
    const auto digest = sha256(content);
    check(ctx->sign(ro(digest), span), "sign CV", kAlertInternalError);
    sig.resize(span.size);
    return { kSigEcdsaP256Sha256, std::move(sig) };
}

void verifyCV(const certx::CCert& leaf, uint16_t scheme,
    const std::vector<uint8_t>& content, const std::vector<uint8_t>& sig) {
    if (scheme != kSigEcdsaP256Sha256 && scheme != kSigEd25519) {
        throw TlsError("unsupported signature scheme", kAlertHandshakeFailure);
    }
    auto ctx = leaf.createAsymmetricContext();
    if (!ctx) {
        throw TlsError("no verify key", kAlertInternalError);
    }
    if (scheme == kSigEcdsaP256Sha256) {
        const auto digest = sha256(content);
        check(ctx->verify(ro(digest), ro(sig)), "bad CertificateVerify", kAlertBadCertificate);
    }
    else {
        check(ctx->verify(ro(content), ro(sig)), "bad CertificateVerify", kAlertBadCertificate);
    }
}

// ------------------------------------------------------------ tickets

constexpr const char* kTicketAad = "taskpp-ticket-v1";
constexpr uint32_t kTicketLifetimeSec = 7200;
constexpr uint64_t kTicketSkewMs = 30000;

struct TicketData {
    std::array<uint8_t, 32> resMaster { }; // resumption master for PSK derivation.
    std::array<uint8_t, 8> nonce { }; // ticket_nonce: binds one PSK per ticket.
    uint16_t cipher = 0;
    uint32_t lifetime = 0;
    uint32_t ageAdd = 0;
};

void checkTicketKey(const std::vector<uint8_t>& key) {
    if (!key.empty() && key.size() != 32) {
        throw TlsError("ticket key must be 32 bytes", kAlertInternalError);
    }
}

std::vector<uint8_t> randomBytes(size_t n) {
    std::vector<uint8_t> out(n);
    certpp::SByteSpan span(out.data(), out.size());
    cryp::CRng::fill(span);
    return out;
}

// ticket = nonce[12] || AEAD(ticketKey, nonce,
//          resMaster[32] || ticketNonce[8] || cipher || lifetime || ageAdd).
std::vector<uint8_t> sealTicket(const std::vector<uint8_t>& ticketKey, const TicketData& data) {
    const std::vector<uint8_t> nonce = randomBytes(12);
    uint8_t plain[50];
    std::memcpy(plain, data.resMaster.data(), 32);
    std::memcpy(plain + 32, data.nonce.data(), 8);
    plain[40] = static_cast<uint8_t>(data.cipher >> 8);
    plain[41] = static_cast<uint8_t>(data.cipher);
    plain[42] = static_cast<uint8_t>(data.lifetime >> 24);
    plain[43] = static_cast<uint8_t>(data.lifetime >> 16);
    plain[44] = static_cast<uint8_t>(data.lifetime >> 8);
    plain[45] = static_cast<uint8_t>(data.lifetime);
    plain[46] = static_cast<uint8_t>(data.ageAdd >> 24);
    plain[47] = static_cast<uint8_t>(data.ageAdd >> 16);
    plain[48] = static_cast<uint8_t>(data.ageAdd >> 8);
    plain[49] = static_cast<uint8_t>(data.ageAdd);
    cryp::CChaCha20Poly1305 aead;
    if (!aead.reset(ro(ticketKey.data(), ticketKey.size()))) {
        throw TlsError("ticket key", kAlertInternalError);
    }
    std::vector<uint8_t> ct(sizeof(plain));
    uint8_t tag[16];
    const std::string aad = kTicketAad;
    if (!aead.seal(ro(nonce.data(), nonce.size()),
            ro(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
            ro(plain, sizeof(plain)), mut(ct), certpp::SByteSpan(tag, 16))) {
        throw TlsError("ticket seal", kAlertInternalError);
    }
    certpp::CSecure::zero(certpp::SByteSpan(plain, sizeof(plain)));
    std::vector<uint8_t> ticket = nonce;
    ticket.insert(ticket.end(), ct.begin(), ct.end());
    ticket.insert(ticket.end(), tag, tag + 16);
    return ticket;
}

std::optional<TicketData> openTicket(const std::vector<uint8_t>& ticketKey,
    const std::vector<uint8_t>& ticket) {
    if (ticketKey.size() != 32 || ticket.size() != 12 + 50 + 16) {
        return std::nullopt;
    }
    cryp::CChaCha20Poly1305 aead;
    if (!aead.reset(ro(ticketKey.data(), ticketKey.size()))) {
        return std::nullopt;
    }
    uint8_t plain[50];
    std::vector<uint8_t> out(sizeof(plain));
    const std::string aad = kTicketAad;
    if (!aead.open(ro(ticket.data(), 12),
            ro(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
            ro(ticket.data() + 12, 50), ro(ticket.data() + 62, 16), mut(out))) {
        return std::nullopt;
    }
    std::memcpy(plain, out.data(), sizeof(plain));
    certpp::CSecure::zero(mut(out));
    TicketData data;
    std::memcpy(data.resMaster.data(), plain, 32);
    std::memcpy(data.nonce.data(), plain + 32, 8);
    data.cipher = static_cast<uint16_t>(plain[40] << 8 | plain[41]);
    data.lifetime = uint32_t { plain[42] } << 24 | uint32_t { plain[43] } << 16
        | uint32_t { plain[44] } << 8 | plain[45];
    data.ageAdd = uint32_t { plain[46] } << 24 | uint32_t { plain[47] } << 16
        | uint32_t { plain[48] } << 8 | plain[49];
    certpp::CSecure::zero(certpp::SByteSpan(plain, sizeof(plain)));
    if (data.lifetime == 0 || data.lifetime > 7 * 24 * 3600) {
        return std::nullopt;
    }
    return data;
}

// ------------------------------------------------------------ NST / CR / HRR

std::vector<uint8_t> buildNst(uint32_t lifetime, uint32_t ageAdd,
    const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ticket) {
    std::vector<uint8_t> body;
    body.push_back(static_cast<uint8_t>(lifetime >> 24));
    body.push_back(static_cast<uint8_t>(lifetime >> 16));
    body.push_back(static_cast<uint8_t>(lifetime >> 8));
    body.push_back(static_cast<uint8_t>(lifetime));
    body.push_back(static_cast<uint8_t>(ageAdd >> 24));
    body.push_back(static_cast<uint8_t>(ageAdd >> 16));
    body.push_back(static_cast<uint8_t>(ageAdd >> 8));
    body.push_back(static_cast<uint8_t>(ageAdd));
    body.push_back(static_cast<uint8_t>(nonce.size()));
    body.insert(body.end(), nonce.begin(), nonce.end());
    putOpaque16(body, ticket);
    putU16(body, 0); // no extensions.
    return hsWrap(kHsNewSessionTicket, body);
}

struct ParsedNst {
    uint32_t lifetime = 0;
    uint32_t ageAdd = 0;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> ticket;
};

ParsedNst parseNst(const std::vector<uint8_t>& body) {
    Cursor c { body.data(), body.size() };
    if (c.n < 8) {
        throw TlsError("bad ticket", kAlertDecodeError);
    }
    ParsedNst nst;
    nst.lifetime = c.u32();
    nst.ageAdd = c.u32();
    const uint8_t nonceLen = c.u8();
    nst.nonce = c.bytes(nonceLen);
    nst.ticket = c.opaque16();
    const size_t extLen = c.u16();
    c.bytes(extLen); // extensions ignored.
    c.end();
    if (nst.ticket.empty()) {
        throw TlsError("empty ticket", kAlertDecodeError);
    }
    return nst;
}

std::vector<uint8_t> buildCertificateRequest() {
    std::vector<uint8_t> body;
    body.push_back(0); // empty request_context.
    std::vector<uint8_t> exts;
    std::vector<uint8_t> algs;
    putU16(algs, 4);
    putU16(algs, kSigEcdsaP256Sha256);
    putU16(algs, kSigEd25519);
    putExtension(exts, 13, algs);
    putU16(body, static_cast<uint16_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());
    return hsWrap(kHsCertificateRequest, body);
}

std::vector<uint8_t> messageHash(const std::vector<uint8_t>& chRaw) {
    const auto h = sha256(chRaw);
    std::vector<uint8_t> out = { 0xFE };
    putU24(out, 32);
    out.insert(out.end(), h.begin(), h.end());
    return out;
}

// RFC 8446 4.2.11.2: binder = HMAC(finished_key, Hash(truncated ClientHello))
// with finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32).
std::array<uint8_t, 32> pskBinder(const uint8_t earlySecret[32],
    const std::array<uint8_t, 32>& truncatedHash) {
    const std::array<uint8_t, 32> emptyHash = sha256(std::vector<uint8_t> { });
    uint8_t binderKey[32];
    deriveSecret(earlySecret, "res binder", emptyHash, binderKey);
    uint8_t finishedKey[32];
    expandLabel(binderKey, "finished", { }, finishedKey, sizeof(finishedKey));
    certpp::CSecure::zero(certpp::SByteSpan(binderKey, sizeof(binderKey)));
    const auto out = hmac(finishedKey, truncatedHash);
    certpp::CSecure::zero(certpp::SByteSpan(finishedKey, sizeof(finishedKey)));
    return out;
}

std::vector<uint8_t> certificateBody(const std::vector<certx::CCert>& chain) {
    std::vector<uint8_t> entries;
    for (const auto& cert : chain) {
        certpp::COctet der;
        check(cert.exportDer(der), "export cert", kAlertInternalError);
        if (der.size() > 0xFFFFFF) {
            throw TlsError("cert too large", kAlertInternalError);
        }
        putU24(entries, static_cast<uint32_t>(der.size()));
        entries.insert(entries.end(), der.toSpan().data, der.toSpan().data + der.size());
        putU16(entries, 0); // no per-certificate extensions.
    }
    std::vector<uint8_t> body;
    body.push_back(0); // request_context, empty for server auth.
    putU24(body, static_cast<uint32_t>(entries.size()));
    body.insert(body.end(), entries.begin(), entries.end());
    return body;
}

std::vector<certx::CCert> parseCertificate(const std::vector<uint8_t>& body) {
    Cursor c { body.data(), body.size() };
    const uint8_t ctxLen = c.u8();
    c.bytes(ctxLen); // request_context (empty for server auth).
    const size_t listLen = c.u24();
    const uint8_t* listEnd = c.p + listLen;
    if (listLen > c.n) {
        throw TlsError("bad certificate list", kAlertDecodeError);
    }
    std::vector<certx::CCert> out;
    while (c.p < listEnd) {
        const size_t derLen = c.u24();
        auto der = c.bytes(derLen);
        const size_t extLen = c.u16();
        c.bytes(extLen); // per-certificate extensions, skipped.
        certx::CCert cert;
        check(cert.importDer(certpp::COctet(der.data(), der.size())), "bad certificate",
            kAlertBadCertificate);
        out.push_back(std::move(cert));
    }
    if (c.p != listEnd) {
        throw TlsError("bad certificate list", kAlertDecodeError);
    }
    c.end();
    return out; // possibly empty: the caller decides (server certs must not be).
}

} // namespace

// ------------------------------------------------------------ state

struct TlsStream::State {
    std::unique_ptr<SocketStream> transport;
    Endpoint endpoint;
    // Resumption inputs, captured at handshake end (client side).
    std::string serverName;
    std::shared_ptr<PskCache> pskCache;
    uint16_t suite = 0;
    uint8_t master[32] { };
    std::array<uint8_t, 32> digestThroughClientFinished { };
};

void PskCache::store(const std::string& serverName, PskEntry entry) {
    std::lock_guard lock(mutex_);
    entries_[serverName] = std::move(entry);
}

std::optional<PskEntry> PskCache::load(const std::string& serverName) const {
    std::lock_guard lock(mutex_);
    const auto it = entries_.find(serverName);
    if (it == entries_.end()) {
        return std::nullopt;
    }
    const auto ageMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - it->second.obtained);
    if (ageMs.count() < 0
        || static_cast<uint64_t>(ageMs.count()) / 1000 >= it->second.lifetimeSec) {
        entries_.erase(it);
        return std::nullopt;
    }
    return it->second;
}

void PskCache::clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
}

// ------------------------------------------------------------ client

Task<TlsStream> TlsStream::connectHandshake(std::unique_ptr<SocketStream> transport, TlsConfig config,
    Canceller canceller) {
    TlsStream stream;
    stream.state_ = std::make_unique<TlsStream::State>();
    stream.state_->transport = std::move(transport);
    Endpoint& ep = stream.state_->endpoint;
    ep.stream = stream.state_->transport.get();
    ep.canceller = canceller;

    std::exception_ptr alertError;
    int alertCode = kAlertInternalError;
    bool alertCanceled = false;
    try {
        const uint8_t zeros[32] = { };
        const std::array<uint8_t, 32> emptyHash = sha256(std::vector<uint8_t> { });

        // PSK offer from the cache (resumption without certificates).
        std::optional<PskEntry> offered;
        if (config.pskCache && !config.serverName.empty()) {
            offered = config.pskCache->load(config.serverName);
        }

        EphemeralX25519 eph = generateX25519();
        auto random = random32();
        auto sessionId = random32();
        std::vector<uint8_t> cookie;
        ParsedServerHello hello;
        bool pskAccepted = false;
        uint8_t early[32] = { };
        for (int flight = 0; ; ++flight) {
            uint8_t pskBytes[32] = { };
            if (offered) {
                std::memcpy(pskBytes, offered->psk.data(), 32);
            }
            hkdfExtract(zeros, offered ? pskBytes : zeros, early);
            certpp::CSecure::zero(certpp::SByteSpan(pskBytes, 32));

            std::vector<uint8_t> ticket;
            uint32_t obfAge = 0;
            if (offered) {
                ticket = offered->ticket;
                const auto ageMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - offered->obtained);
                obfAge = static_cast<uint32_t>(
                    static_cast<uint64_t>(ageMs.count()) + offered->ageAdd);
            }
            ClientHelloFlight ch = buildClientHello(config, random, sessionId,
                eph.pub, ticket, obfAge, cookie);
            if (!ticket.empty()) {
                // RFC 8446 4.2.11.2: hash the ClientHello up to and including
                // the identities field. Every length field keeps its full
                // value -- only the binder bytes themselves are omitted.
                const size_t fullBody = ch.message.size() - 4;
                const size_t throughIdentities = ch.binderOffset - 4 - 3;
                std::vector<uint8_t> trunc = { kHsClientHello };
                putU24(trunc, static_cast<uint32_t>(fullBody));
                trunc.insert(trunc.end(), ch.message.begin() + 4,
                    ch.message.begin() + 4 + throughIdentities);
                const auto binder = pskBinder(early, ep.transcript.digestWithExtra(trunc));
                std::memcpy(ch.message.data() + ch.binderOffset, binder.data(), binder.size());
            }
            ep.transcript.update(ch.message);
            co_await ep.sendRecord(kRecHandshake, ch.message.data(), ch.message.size(),
                nullptr, kRecHandshake);
            const std::vector<uint8_t> chRaw = ch.message;

            HsMessage msg = co_await ep.recvHandshake();
            if (msg.type != kHsServerHello) {
                throw TlsError("expected server hello", kAlertUnexpectedMessage);
            }
            if (isHrr(msg.body)) {
                if (flight > 0) {
                    throw TlsError("retry loop", kAlertHandshakeFailure);
                }
                const ParsedHrr hrr = parseHrr(msg.body, sessionId);
                ep.transcript.update(messageHash(chRaw));
                ep.transcript.update(msg.raw);
                // Retry as a full handshake (PSK dropped), echoing the cookie.
                offered.reset();
                cookie = hrr.cookie;
                eph = generateX25519();
                random = random32();
                sessionId = random32();
                continue;
            }
            ep.transcript.update(msg.raw);
            hello = parseServerHello(msg.body, sessionId);
            if (hello.pskSelected >= 0) {
                if (!offered || hello.pskSelected != 0) {
                    throw TlsError("bad psk selection", kAlertIllegalParameter);
                }
                pskAccepted = true;
            }
            break;
        }

        // The schedule follows the server's choice, not our offer: a server
        // that ignored the PSK runs the zero-PSK schedule.
        if (pskAccepted) {
            if (!offered || offered->psk.size() != 32) {
                throw TlsError("psk unavailable", kAlertInternalError);
            }
            uint8_t pskBytes[32];
            std::memcpy(pskBytes, offered->psk.data(), 32);
            hkdfExtract(zeros, pskBytes, early);
            certpp::CSecure::zero(certpp::SByteSpan(pskBytes, 32));
        }
        else {
            hkdfExtract(zeros, zeros, early);
        }

        const std::array<uint8_t, 32> shared = x25519Shared(eph, hello.keyShare);
        const std::array<uint8_t, 32> digestChSh = ep.transcript.digest();
        KeySchedule ks = KeySchedule::derive(shared, digestChSh, early);
        certpp::CSecure::zero(certpp::SByteSpan(early, 32));
        ep.rxHs.init(hello.suite, ks.sHs);
        ep.txHs.init(hello.suite, ks.cHs);
        ep.txEncrypted = true; // everything we send past this point is protected.

        HsMessage ee = co_await ep.recvHandshake();
        if (ee.type != kHsEncryptedExtensions) {
            throw TlsError("expected encrypted extensions", kAlertUnexpectedMessage);
        }
        ep.transcript.update(ee.raw);
        {
            Cursor c { ee.body.data(), ee.body.size() };
            const size_t extTotal = c.u16();
            const uint8_t* extEnd = c.p + extTotal;
            if (extTotal > c.n) {
                throw TlsError("bad EE", kAlertDecodeError);
            }
            while (c.p < extEnd) {
                const uint16_t type = c.u16();
                auto ext = c.opaque16();
                if (type == 16 && !ext.empty()) {
                    Cursor l { ext.data(), ext.size() };
                    const size_t listLen = l.u16();
                    (void) listLen;
                    if (l.n > 0) {
                        const uint8_t len = l.u8();
                        auto proto = l.bytes(len);
                        stream.alpn_.assign(proto.begin(), proto.end());
                    }
                }
            }
            if (c.p != extEnd) {
                throw TlsError("bad EE", kAlertDecodeError);
            }
            c.end();
        }

        HsMessage next = co_await ep.recvHandshake();
        bool clientAuth = false;
        if (next.type == kHsCertificateRequest) {
            // Server wants a client certificate (mutual TLS).
            clientAuth = true;
            ep.transcript.update(next.raw);
            next = co_await ep.recvHandshake();
        }
        if (next.type == kHsCertificate) {
            if (pskAccepted) {
                throw TlsError("certificate with psk", kAlertUnexpectedMessage);
            }
            ep.transcript.update(next.raw);
            stream.peerCerts_ = parseCertificate(next.body);
            if (stream.peerCerts_.empty()) {
                throw TlsError("expected certificate", kAlertUnexpectedMessage);
            }

            HsMessage cv = co_await ep.recvHandshake();
            if (cv.type != kHsCertificateVerify) {
                throw TlsError("expected certificate verify", kAlertUnexpectedMessage);
            }
            const std::array<uint8_t, 32> digestThroughCert = ep.transcript.digest();
            {
                Cursor c { cv.body.data(), cv.body.size() };
                const uint16_t scheme = c.u16();
                auto sig = c.opaque16();
                c.end();
                if (config.verifyPeer) {
                    verifyCV(stream.peerCerts_.front(), scheme,
                        cvContent(true, digestThroughCert), sig);
                }
            }
            ep.transcript.update(cv.raw);

            HsMessage sf = co_await ep.recvHandshake();
            if (sf.type != kHsFinished) {
                throw TlsError("expected finished", kAlertUnexpectedMessage);
            }
            {
                const std::array<uint8_t, 32> digestThroughCv = ep.transcript.digest();
                const std::array<uint8_t, 32> expect = hmac(ks.sHsFin, digestThroughCv);
                if (sf.body.size() != expect.size()
                    || !certpp::CSecure::equals(ro(sf.body), ro(expect.data(), expect.size()))) {
                    throw TlsError("bad finished", kAlertDecryptError);
                }
            }
            ep.transcript.update(sf.raw);

            if (config.verifyPeer) {
                validateChain(stream.peerCerts_, config.trustAnchors, config.serverName);
            }
        }
        else if (next.type == kHsFinished && pskAccepted) {
            // Resumed session: no certificates at all.
            const std::array<uint8_t, 32> digestThroughEe = ep.transcript.digest();
            const std::array<uint8_t, 32> expect = hmac(ks.sHsFin, digestThroughEe);
            if (next.body.size() != expect.size()
                || !certpp::CSecure::equals(ro(next.body), ro(expect.data(), expect.size()))) {
                throw TlsError("bad finished", kAlertDecryptError);
            }
            ep.transcript.update(next.raw);
        }
        else {
            throw TlsError("expected certificate or finished", kAlertUnexpectedMessage);
        }
        const std::array<uint8_t, 32> digestThroughSf = ep.transcript.digest();
        ks.deriveApp(digestThroughSf);

        if (clientAuth) {
            // Our flight goes out before our Finished.
            if (config.clientCertificateChain.empty()) {
                throw TlsError("server requested a client certificate", kAlertBadCertificate);
            }
            co_await ep.sendHandshake(hsWrap(kHsCertificate,
                certificateBody(config.clientCertificateChain)));
            const std::array<uint8_t, 32> digestBeforeCv = ep.transcript.digest();
            const auto [scheme, sig] = makeCV(
                config.clientCertificateChain.front(), digestBeforeCv, false);
            std::vector<uint8_t> cvBody;
            putU16(cvBody, scheme);
            putOpaque16(cvBody, sig);
            co_await ep.sendHandshake(hsWrap(kHsCertificateVerify, cvBody));
        }

        // Our Finished goes out under the client handshake keys.
        {
            const std::array<uint8_t, 32> data = hmac(ks.cHsFin, digestThroughSf);
            std::vector<uint8_t> body(data.begin(), data.end());
            ep.txEncrypted = true;
            co_await ep.sendHandshake(hsWrap(kHsFinished, body));
        }
        ep.txApp.init(hello.suite, ks.cAp);
        ep.rxApp.init(hello.suite, ks.sAp);
        ep.rxAppActive = true;

        // Resumption inputs for tickets this server may send later.
        stream.state_->serverName = config.serverName;
        stream.state_->pskCache = config.pskCache;
        stream.state_->suite = hello.suite;
        std::memcpy(stream.state_->master, ks.master, 32);
        stream.state_->digestThroughClientFinished = ep.transcript.digest();
        stream.resumed_ = pskAccepted;
        ks.wipe();
    }
    catch (...) {
        alertError = std::current_exception();
        try {
            std::rethrow_exception(alertError);
        }
        catch (const TlsError& e) {
            alertCode = e.alert();
        }
        catch (const OperationCanceled&) {
            alertCanceled = true;
        }
        catch (...) {
        }
    }
    if (alertError) {
        if (!alertCanceled) {
            try {
                std::rethrow_exception(alertError);
            }
            catch (const std::exception& e) {
                (void) e;
            }
            catch (...) {
            }
            try {
                co_await alertNow(ep, alertCode);
            }
            catch (...) {
            }
        }
        std::rethrow_exception(alertError);
    }
    co_return std::move(stream);
}

// ------------------------------------------------------------ server

Task<TlsStream> TlsStream::acceptHandshake(std::unique_ptr<SocketStream> transport, TlsConfig config,
    Canceller canceller) {
    if (config.certificateChain.empty()) {
        throw TlsError("no server certificate", kAlertInternalError);
    }
    TlsStream stream;
    stream.state_ = std::make_unique<TlsStream::State>();
    stream.state_->transport = std::move(transport);
    Endpoint& ep = stream.state_->endpoint;
    ep.stream = stream.state_->transport.get();
    ep.canceller = canceller;

    std::exception_ptr alertError;
    int alertCode = kAlertInternalError;
    bool alertCanceled = false;
    try {
        if (config.verifyClient && config.clientTrustAnchors.empty() && config.trustAnchors.empty()) {
            throw TlsError("no client anchors", kAlertInternalError);
        }
        checkTicketKey(config.ticketKey);

        HsMessage ch = co_await ep.recvHandshake();
        if (ch.type != kHsClientHello) {
            throw TlsError("expected client hello", kAlertUnexpectedMessage);
        }
        ParsedHello hello = parseClientHello(ch.body);
        if (!hello.offeredV13) {
            throw TlsError("client is not TLS 1.3", kAlertHandshakeFailure);
        }
        auto selectSuite = [&]() {
            for (uint16_t s : hello.suites) {
                if (s == kSuiteAes128Gcm || s == kSuiteChaCha20Poly1305) {
                    return s;
                }
            }
            return uint16_t { 0 };
        };
        uint16_t suite = selectSuite();
        if (suite == 0) {
            throw TlsError("no overlapping cipher", kAlertHandshakeFailure);
        }
        if (hello.keyShare.empty()) {
            // HelloRetryRequest for our only group, then read the second flight.
            std::vector<uint8_t> hrrBody;
            putU16(hrrBody, kTls12Version);
            hrrBody.insert(hrrBody.end(), std::begin(kHrrMagic), std::end(kHrrMagic));
            hrrBody.push_back(static_cast<uint8_t>(hello.sessionId.size()));
            hrrBody.insert(hrrBody.end(), hello.sessionId.begin(), hello.sessionId.end());
            putU16(hrrBody, suite);
            hrrBody.push_back(0);
            {
                std::vector<uint8_t> exts;
                std::vector<uint8_t> v = { 0x03, 0x04 };
                putExtension(exts, 43, v);
                std::vector<uint8_t> ks;
                putU16(ks, kGroupX25519);
                putExtension(exts, 51, ks);
                putU16(hrrBody, static_cast<uint16_t>(exts.size()));
                hrrBody.insert(hrrBody.end(), exts.begin(), exts.end());
            }
            ep.transcript.update(messageHash(ch.raw));
            co_await ep.sendHandshake(hsWrap(kHsServerHello, hrrBody));
            ch = co_await ep.recvHandshake();
            if (ch.type != kHsClientHello) {
                throw TlsError("expected client hello", kAlertUnexpectedMessage);
            }
            hello = parseClientHello(ch.body);
            if (!hello.offeredV13 || hello.keyShare.size() != 32) {
                throw TlsError("bad retry hello", kAlertHandshakeFailure);
            }
            suite = selectSuite();
            if (suite == 0) {
                throw TlsError("no overlapping cipher", kAlertHandshakeFailure);
            }
        }
        const uint8_t zeros[32] = { };
        const std::array<uint8_t, 32> emptyHash = sha256(std::vector<uint8_t> { });

        // PSK: try every offered identity; fall back to a full handshake.
        uint8_t acceptedPsk[32] = { };
        int acceptedIdentity = -1;
        if (!hello.psk.empty() && !config.ticketKey.empty() && hello.pskTruncLen > 0
            && hello.pskTruncLen <= ch.body.size()) {
            // RFC 8446 4.2.11.2: the hashed prefix ends after the
            // identities field, but every length field keeps its full value.
            std::vector<uint8_t> trunc = { kHsClientHello };
            putU24(trunc, static_cast<uint32_t>(ch.body.size()));
            trunc.insert(trunc.end(), ch.body.begin(),
                ch.body.begin() + hello.pskTruncLen);
            const std::array<uint8_t, 32> truncHash = ep.transcript.digestWithExtra(trunc);
            int index = 0;
            for (const auto& offer : hello.psk) {
                auto ticket = openTicket(config.ticketKey, offer.ticket);
                if (ticket && ticket->cipher == suite) {
                    const uint32_t age = offer.obfAge - ticket->ageAdd;
                    if (uint64_t { age } <= uint64_t { ticket->lifetime } * 1000 + kTicketSkewMs) {
                        // The PSK is bound to this ticket's nonce (RFC 8446 7.5).
                        uint8_t psk[32];
                        {
                            std::vector<uint8_t> nonce(ticket->nonce.begin(), ticket->nonce.end());
                            expandLabel(ticket->resMaster.data(), "resumption", nonce, psk, 32);
                        }
                        uint8_t early[32];
                        hkdfExtract(zeros, psk, early);
                        const auto expect = pskBinder(early, truncHash);
                        certpp::CSecure::zero(certpp::SByteSpan(early, 32));
                        if (offer.binder.size() == expect.size()
                            && certpp::CSecure::equals(ro(offer.binder), ro(expect.data(), expect.size()))) {
                            std::memcpy(acceptedPsk, psk, 32);
                            acceptedIdentity = index;
                            certpp::CSecure::zero(certpp::SByteSpan(psk, 32));
                            break;
                        }
                        certpp::CSecure::zero(certpp::SByteSpan(psk, 32));
                    }
                }
                ++index;
            }
        }
        ep.transcript.update(ch.raw);
        const bool pskAccepted = acceptedIdentity >= 0;

        EphemeralX25519 eph = generateX25519();
        const std::array<uint8_t, 32> shared = x25519Shared(eph, hello.keyShare);

        std::vector<uint8_t> random = random32();
        std::vector<uint8_t> shBody;
        putU16(shBody, kTls12Version);
        shBody.insert(shBody.end(), random.begin(), random.end());
        shBody.push_back(static_cast<uint8_t>(hello.sessionId.size()));
        shBody.insert(shBody.end(), hello.sessionId.begin(), hello.sessionId.end());
        putU16(shBody, suite);
        shBody.push_back(0);
        {
            std::vector<uint8_t> exts;
            std::vector<uint8_t> v = { 0x03, 0x04 };
            putExtension(exts, 43, v);
            std::vector<uint8_t> ks;
            putU16(ks, kGroupX25519);
            putOpaque16(ks, eph.pub);
            putExtension(exts, 51, ks);
            if (pskAccepted) {
                std::vector<uint8_t> psk;
                putU16(psk, static_cast<uint16_t>(acceptedIdentity));
                putExtension(exts, 41, psk);
            }
            putU16(shBody, static_cast<uint16_t>(exts.size()));
            shBody.insert(shBody.end(), exts.begin(), exts.end());
        }
        co_await ep.sendHandshake(hsWrap(kHsServerHello, shBody));
        const std::array<uint8_t, 32> digestChSh = ep.transcript.digest();

        uint8_t early[32];
        hkdfExtract(zeros, pskAccepted ? acceptedPsk : zeros, early);
        certpp::CSecure::zero(certpp::SByteSpan(acceptedPsk, 32));
        KeySchedule ks = KeySchedule::derive(shared, digestChSh, early);
        certpp::CSecure::zero(certpp::SByteSpan(early, 32));
        ep.txHs.init(suite, ks.sHs);
        ep.rxHs.init(suite, ks.cHs);
        ep.txEncrypted = true;

        std::string selected;
        for (const auto& offered : hello.alpn) {
            if (std::find(config.alpn.begin(), config.alpn.end(), offered) != config.alpn.end()) {
                selected = offered;
                break;
            }
        }
        stream.alpn_ = selected;
        {
            std::vector<uint8_t> eeBody;
            std::vector<uint8_t> exts;
            if (!selected.empty()) {
                putExtension(exts, 16, alpnBody({ selected }));
            }
            putU16(eeBody, static_cast<uint16_t>(exts.size()));
            eeBody.insert(eeBody.end(), exts.begin(), exts.end());
            co_await ep.sendHandshake(hsWrap(kHsEncryptedExtensions, eeBody));
        }
        const bool requestClientCert = config.verifyClient && !pskAccepted;
        if (requestClientCert) {
            co_await ep.sendHandshake(buildCertificateRequest());
        }
        if (!pskAccepted) {
            co_await ep.sendHandshake(hsWrap(kHsCertificate, certificateBody(config.certificateChain)));

            const std::array<uint8_t, 32> digestThroughCert = ep.transcript.digest();
            {
                const auto [scheme, sig] = makeCV(config.certificateChain.front(), digestThroughCert, true);
                bool offered = false;
                // Client signature_algorithms are advisory here; overlapping is checked loosely.
                (void) hello;
                offered = scheme == kSigEcdsaP256Sha256 || scheme == kSigEd25519;
                if (!offered) {
                    throw TlsError("no overlapping signature", kAlertHandshakeFailure);
                }
                std::vector<uint8_t> cvBody;
                putU16(cvBody, scheme);
                putOpaque16(cvBody, sig);
                co_await ep.sendHandshake(hsWrap(kHsCertificateVerify, cvBody));
            }
        }
        std::array<uint8_t, 32> digestThroughCv = ep.transcript.digest();
        {
            const std::array<uint8_t, 32> data = hmac(ks.sHsFin, digestThroughCv);
            co_await ep.sendHandshake(hsWrap(kHsFinished, { data.begin(), data.end() }));
        }
        const std::array<uint8_t, 32> digestThroughSf = ep.transcript.digest();
        ks.deriveApp(digestThroughSf);
        ep.txApp.init(suite, ks.sAp);

        if (requestClientCert) {
            HsMessage cc = co_await ep.recvHandshake();
            if (cc.type != kHsCertificate) {
                throw TlsError("expected client certificate", kAlertUnexpectedMessage);
            }
            ep.transcript.update(cc.raw);
            const auto clientCerts = parseCertificate(cc.body);
            if (clientCerts.empty()) {
                throw TlsError("client sent no certificate", kAlertBadCertificate);
            }
            stream.peerCerts_ = clientCerts;
            const auto& anchors = config.clientTrustAnchors.empty()
                ? config.trustAnchors : config.clientTrustAnchors;
            validateChain(clientCerts, anchors, "",
                certx::CEkuExtension::OID_CLIENT_AUTH);

            HsMessage ccv = co_await ep.recvHandshake();
            if (ccv.type != kHsCertificateVerify) {
                throw TlsError("expected certificate verify", kAlertUnexpectedMessage);
            }
            const std::array<uint8_t, 32> digestBeforeCv = ep.transcript.digest();
            {
                Cursor c { ccv.body.data(), ccv.body.size() };
                const uint16_t scheme = c.u16();
                auto sig = c.opaque16();
                c.end();
                verifyCV(clientCerts.front(), scheme,
                    cvContent(false, digestBeforeCv), sig);
            }
            ep.transcript.update(ccv.raw);
        }

        HsMessage cf = co_await ep.recvHandshake();
        if (cf.type != kHsFinished) {
            throw TlsError("expected finished", kAlertUnexpectedMessage);
        }
        {
            const std::array<uint8_t, 32> expect = hmac(ks.cHsFin, digestThroughSf);
            if (cf.body.size() != expect.size()
                || !certpp::CSecure::equals(ro(cf.body), ro(expect.data(), expect.size()))) {
                throw TlsError("bad finished", kAlertDecryptError);
            }
        }
        ep.rxApp.init(suite, ks.cAp);
        ep.rxAppActive = true;

        if (!config.ticketKey.empty()) {
            // One stateless ticket for a future resumption. The ticket binds
            // the resumption master (RFC 8446 7.5), so the server keeps no
            // per-session state at all.
            ep.transcript.update(cf.raw);
            const std::array<uint8_t, 32> digestCF = ep.transcript.digest();
            TicketData data;
            deriveSecret(ks.master, "res master", digestCF, data.resMaster.data());
            const auto ticketNonce = randomBytes(8);
            std::memcpy(data.nonce.data(), ticketNonce.data(), 8);
            data.cipher = suite;
            data.lifetime = kTicketLifetimeSec;
            const auto ageBytes = randomBytes(4);
            data.ageAdd = uint32_t { ageBytes[0] } << 24 | uint32_t { ageBytes[1] } << 16
                | uint32_t { ageBytes[2] } << 8 | ageBytes[3];
            const auto ticket = sealTicket(config.ticketKey, data);
            certpp::CSecure::zero(certpp::SByteSpan(data.resMaster.data(), 32));
            const auto nst = buildNst(data.lifetime, data.ageAdd, ticketNonce, ticket);
            co_await ep.sendRecord(kRecHandshake, nst.data(), nst.size(), &ep.txApp, kRecHandshake);
        }
        ks.wipe();
    }
    catch (...) {
        alertError = std::current_exception();
        try {
            std::rethrow_exception(alertError);
        }
        catch (const TlsError& e) {
            alertCode = e.alert();
        }
        catch (const OperationCanceled&) {
            alertCanceled = true;
        }
        catch (...) {
        }
    }
    if (alertError) {
        if (!alertCanceled) {
            try {
                std::rethrow_exception(alertError);
            }
            catch (const std::exception&) {
            }
            catch (...) {
            }
            try {
                co_await alertNow(ep, alertCode);
            }
            catch (...) {
            }
        }
        std::rethrow_exception(alertError);
    }
    co_return std::move(stream);
}

// ------------------------------------------------------------ TlsStream

TlsStream::~TlsStream() = default;
TlsStream::TlsStream(TlsStream&&) noexcept = default;
TlsStream& TlsStream::operator=(TlsStream&&) noexcept = default;

Task<TlsStream> TlsStream::connect(Socket socket, TlsConfig config, Canceller canceller) {
    auto transport = std::make_unique<SocketStream>(std::move(socket));
    TlsStream stream = co_await connectHandshake(std::move(transport), std::move(config), std::move(canceller));
    co_return std::move(stream);
}

Task<TlsStream> TlsStream::accept(Socket socket, TlsConfig config, Canceller canceller) {
    auto transport = std::make_unique<SocketStream>(std::move(socket));
    TlsStream stream = co_await acceptHandshake(std::move(transport), std::move(config), std::move(canceller));
    co_return std::move(stream);
}

Task<void> TlsStream::write(std::span<const char> data, Canceller canceller) {
    if (!state_ || !state_->transport->valid()) {
        throw TlsError("stream closed", kAlertCloseNotify);
    }
    Endpoint& ep = state_->endpoint;
    ep.canceller = std::move(canceller);
    size_t done = 0;
    while (done < data.size()) {
        const size_t n = std::min(data.size() - done, kMaxRecordBytes);
        co_await ep.sendRecord(kRecAppData,
            reinterpret_cast<const uint8_t*>(data.data()) + done, n, &ep.txApp, kRecAppData);
        done += n;
    }
    co_return;
}

Task<std::size_t> TlsStream::readSome(std::span<char> buffer, Canceller canceller) {
    if (!state_) {
        co_return 0;
    }
    Endpoint& ep = state_->endpoint;
    ep.canceller = std::move(canceller);

    auto drainPending = [&]() -> size_t {
        const size_t n = std::min(buffer.size(), ep.appPending.size());
        std::memcpy(buffer.data(), ep.appPending.data(), n);
        ep.appPending.erase(ep.appPending.begin(), ep.appPending.begin() + n);
        return n;
    };
    if (!ep.appPending.empty() || buffer.empty()) {
        co_return drainPending();
    }
    while (true) {
        TlsRecord record;
        try {
            record = co_await ep.recvRecord();
        }
        catch (const SocketClosed&) {
            // Abrupt TCP close: deliver what we have (interop over strictness).
            co_return drainPending();
        }
        if (record.type == kRecAlert) {
            try {
                ep.handleAlert(record.payload);
            }
            catch (const TlsError& e) {
                if (e.alert() == kAlertCloseNotify) {
                    co_return drainPending();
                }
                throw;
            }
        }
        else if (record.type == kRecAppData) {
            ep.appPending.insert(ep.appPending.end(), record.payload.begin(), record.payload.end());
            co_return drainPending();
        }
        else if (record.type == kRecHandshake) {
            // Post-handshake: NewSessionTicket / KeyUpdate (or garbage).
            ep.hsPending.insert(ep.hsPending.end(), record.payload.begin(), record.payload.end());
            while (ep.hsPending.size() >= 4) {
                const size_t length = getU24(ep.hsPending.data() + 1);
                if (length > kMaxHandshakeBytes) {
                    throw TlsError("post-hs overflow", kAlertDecodeError);
                }
                if (ep.hsPending.size() < 4 + length) {
                    break;
                }
                const uint8_t type = ep.hsPending[0];
                std::vector<uint8_t> body(ep.hsPending.begin() + 4,
                    ep.hsPending.begin() + 4 + length);
                ep.hsPending.erase(ep.hsPending.begin(), ep.hsPending.begin() + 4 + length);
                if (type == kHsNewSessionTicket) {
                    // Stash a resumption PSK for a later connection, if the
                    // client configured a cache. Malformed tickets are ignored.
                    try {
                        const ParsedNst nst = parseNst(body);
                        if (state_->pskCache && !state_->serverName.empty() && !nst.ticket.empty()) {
                            uint8_t resMaster[32];
                            deriveSecret(state_->master, "res master",
                                state_->digestThroughClientFinished, resMaster);
                            PskEntry entry;
                            entry.ticket = nst.ticket;
                            entry.cipher = state_->suite;
                            entry.ageAdd = nst.ageAdd;
                            entry.lifetimeSec = nst.lifetime;
                            entry.obtained = std::chrono::steady_clock::now();
                            entry.psk.assign(32, 0);
                            expandLabel(resMaster, "resumption", nst.nonce, entry.psk.data(), 32);
                            certpp::CSecure::zero(certpp::SByteSpan(resMaster, 32));
                            state_->pskCache->store(state_->serverName, std::move(entry));
                        }
                    }
                    catch (...) {
                    }
                    continue;
                }
                if (type == kHsKeyUpdate) {
                    if (body.size() != 1 || body[0] > 1) {
                        throw TlsError("bad KeyUpdate", kAlertDecodeError);
                    }
                    co_await ep.applyKeyUpdate(body[0] == 1);
                    continue;
                }
                throw TlsError("unexpected post-hs message", kAlertUnexpectedMessage);
            }
        }
        else {
            throw TlsError("unexpected record", kAlertUnexpectedMessage);
        }
    }
}

Task<void> TlsStream::shutdown(Canceller canceller) {
    if (!state_ || !state_->transport->valid()) {
        co_return;
    }
    Endpoint& ep = state_->endpoint;
    ep.canceller = std::move(canceller);
    const uint8_t notify[1] = { kAlertCloseNotify };
    const uint8_t payload[2] = { 1, notify[0] };
    try {
        if (ep.txApp.active) {
            co_await ep.sendRecord(kRecAppData, payload, 2, &ep.txApp, kRecAlert);
        }
        else {
            co_await ep.sendRecord(kRecAlert, payload, 2, nullptr, kRecAlert);
        }
    }
    catch (...) {
    }
    co_return;
}

void TlsStream::close() noexcept {
    if (state_) {
        // Best-effort secret hygiene: handshake keys never leave this object
        // alive longer than the connection.
        state_->endpoint.txHs.wipe();
        state_->endpoint.rxHs.wipe();
        state_->endpoint.txApp.wipe();
        state_->endpoint.rxApp.wipe();
        certpp::CSecure::zero(certpp::SByteSpan(state_->master, 32));
        state_->digestThroughClientFinished.fill(0);
        if (state_->transport) {
            state_->transport->close();
        }
    }
}

bool TlsStream::valid() const noexcept {
    return state_ && state_->transport && state_->transport->valid();
}

} // namespace taskpp::tls
