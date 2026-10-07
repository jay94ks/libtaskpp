#pragma once
// TLS 1.3 (RFC 8446) over any connected Socket, crypto/cert/hash exclusively
// from libcertpp. All names live in `taskpp::tls`.
//
// Supported: X25519 key exchange; AES-128-GCM and ChaCha20-Poly1305;
// ECDSA P-256 and Ed25519 certificates; session resumption via PSK tickets
// (no early data); mutual TLS via CertificateRequest; HelloRetryRequest;
// ALPN; SNI. Path validation (dates, basicConstraints, keyUsage, EKU,
// SAN/CN, anchor trust) is implemented here -- libcertpp checks single
// links only.
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Stream.hpp>
#include <taskpp/core/Task.hpp>
#include <taskpp/socket/Socket.hpp>
#include <taskpp/socket/SocketStream.hpp>

#include <certpp.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace taskpp::tls {

/** Thrown for handshake and record failures; carries a TLS alert code. */
class TlsError : public std::runtime_error {
public:
    explicit TlsError(const std::string& what, int alert = 80)
        : std::runtime_error("tls: " + what), alert_(alert) { }

    /** Alert description byte (80 = internal_error when nothing fits). */
    int alert() const noexcept { return alert_; }

private:
    int alert_;
};

/** One stored session ticket (client side). */
struct PskEntry {
    std::vector<uint8_t> ticket; // opaque server ticket to echo back.
    std::vector<uint8_t> psk; // 32-byte resumption PSK.
    uint16_t cipher = 0; // suite the ticket was issued under.
    uint32_t ageAdd = 0; // ticket_age_add from NewSessionTicket.
    uint32_t lifetimeSec = 0; // ticket_lifetime from NewSessionTicket.
    std::chrono::steady_clock::time_point obtained;
};

/**
 * Client-side session cache, keyed by server name. Share one between
 * connections (`TlsConfig::pskCache`) to resume sessions. Thread-safe.
 */
class PskCache {
public:
    PskCache() = default;

    void store(const std::string& serverName, PskEntry entry);
    std::optional<PskEntry> load(const std::string& serverName) const;
    void clear();

private:
    mutable std::mutex mutex_;
    mutable std::map<std::string, PskEntry> entries_;
};

struct TlsConfig {
    /** Verify the peer chain (dates, CA chain, key usage, SAN, anchor). */
    bool verifyPeer = true;
    /** Trust anchors for chain building (client side, and mTLS clients). */
    std::vector<certpp::x509::CCert> trustAnchors;
    /** SNI + hostname check; empty skips both (IP literals never send SNI). */
    std::string serverName;
    /** Client offer / server supported list; first overlap wins. */
    std::vector<std::string> alpn = { "h2", "http/1.1" };
    /** Server chain, leaf first; the leaf carries its private key. */
    std::vector<certpp::x509::CCert> certificateChain;
    /**
     * Server: 32-byte key to encrypt session tickets; empty disables ticket
     * issuance (no resumption offered). Reuse one config across accepts.
     */
    std::vector<uint8_t> ticketKey;
    /** Client: shared ticket store; null disables resumption. */
    std::shared_ptr<PskCache> pskCache;
    /** Server: request a client certificate (mutual TLS). */
    bool verifyClient = false;
    /** Trust anchors for client chains (mTLS); falls back to trustAnchors. */
    std::vector<certpp::x509::CCert> clientTrustAnchors;
    /** Client chain for mutual TLS, leaf first with its private key. */
    std::vector<certpp::x509::CCert> clientCertificateChain;
};

/**
 * A TLS 1.3 byte stream. Handshake runs inside connect()/accept(); afterwards
 * it is a plain `Stream` (works under H1/H2 connections).
 */
class TlsStream : public Stream {
public:
    /** Client handshake over a connected socket. */
    static Task<TlsStream> connect(Socket socket, TlsConfig config, Canceller canceller = { });
    /** Server handshake over an accepted socket. */
    static Task<TlsStream> accept(Socket socket, TlsConfig config, Canceller canceller = { });

    TlsStream(TlsStream&&) noexcept;
    TlsStream& operator=(TlsStream&&) noexcept;
    ~TlsStream();

    Task<void> write(std::span<const char> data, Canceller canceller = { }) override;
    Task<std::size_t> readSome(std::span<char> buffer, Canceller canceller = { }) override;

    /** Sends close_notify (best effort), then closes the socket. */
    Task<void> shutdown(Canceller canceller = { });
    void close() noexcept override;
    bool valid() const noexcept override;

    const std::string& negotiatedAlpn() const noexcept { return alpn_; }
    /** True when this session resumed (PSK handshake, no certificates). */
    bool resumed() const noexcept { return resumed_; }
    const std::vector<certpp::x509::CCert>& peerCertificates() const noexcept { return peerCerts_; }

private:
    struct State;

    static Task<TlsStream> connectHandshake(std::unique_ptr<SocketStream> transport,
        TlsConfig config, Canceller canceller);
    static Task<TlsStream> acceptHandshake(std::unique_ptr<SocketStream> transport,
        TlsConfig config, Canceller canceller);

    TlsStream() = default;

    std::unique_ptr<State> state_;
    std::string alpn_;
    bool resumed_ = false;
    std::vector<certpp::x509::CCert> peerCerts_;
};

} // namespace taskpp::tls
