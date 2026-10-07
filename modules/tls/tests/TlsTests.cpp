#include "TestHarness.hpp"
#include "TestCerts.hpp"

#include <taskpp/http/Http.hpp>
#include <taskpp/core/Core.hpp>
#include <taskpp/core/WhenAll.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

using namespace taskpp;
using namespace taskpp::http;
using namespace taskpp::tls;
using namespace testcerts;
namespace cc = certpp::crypto;

TEST(tls_loopback_echo) {
    Fixture fx;
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();

    w->push([](Socket* l, Fixture* fx) -> Task<void> {
        Socket raw = co_await l->accept();
        TlsStream server = co_await TlsStream::accept(std::move(raw), fx->serverConfig());
        CHECK(co_await echoOnce(&server) == "hello");
    }(&listener, &fx));

    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    TlsStream client = w->sync_wait(TlsStream::connect(std::move(raw), fx.clientConfig()));
    const std::string out = "hello";
    w->sync_wait(client.write(std::span(out.data(), out.size())));
    std::string in(5, '\0');
    w->sync_wait(client.readExact(std::span(in.data(), in.size())));
    CHECK(in == "hello");
    CHECK(client.negotiatedAlpn() == "h2");
    CHECK(!client.peerCertificates().empty());
    w->wait();
}

TEST(tls_ed25519_leaf) {
    Fixture fx;
    auto edPair = generateKey(cc::EASYM_ED25519, 256);
    fx.leaf = makeLeaf(edPair, fx.ca, fx.caPair);
    fx.leafPair = edPair;

    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();

    w->push([](Socket* l, Fixture* fx) -> Task<void> {
        Socket raw = co_await l->accept();
        TlsStream server = co_await TlsStream::accept(std::move(raw), fx->serverConfig());
        CHECK(co_await echoOnce(&server) == "hello");
    }(&listener, &fx));

    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    TlsStream client = w->sync_wait(TlsStream::connect(std::move(raw), fx.clientConfig()));
    const std::string out = "hello";
    w->sync_wait(client.write(std::span(out.data(), out.size())));
    std::string in(5, '\0');
    w->sync_wait(client.readExact(std::span(in.data(), in.size())));
    CHECK(in == "hello");
    w->wait();
}

TEST(tls_wrong_host_fails) {
    Fixture fx;
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();

    w->push([](Socket* l, Fixture* fx) -> Task<void> {
        Socket raw = co_await l->accept();
        try {
            TlsStream server = co_await TlsStream::accept(std::move(raw), fx->serverConfig());
            (void) server;
        }
        catch (const TlsError&) {
        }
    }(&listener, &fx));

    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    CHECK_THROWS(TlsError, w->sync_wait(TlsStream::connect(std::move(raw), fx.clientConfig("wrong.example"))));
    w->wait();
}

TEST(tls_unknown_ca_fails) {
    Fixture fx;
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();

    w->push([](Socket* l, Fixture* fx) -> Task<void> {
        Socket raw = co_await l->accept();
        try {
            TlsStream server = co_await TlsStream::accept(std::move(raw), fx->serverConfig());
            (void) server;
        }
        catch (const TlsError&) {
        }
    }(&listener, &fx));

    TlsConfig client;
    client.serverName = "localhost"; // no anchors: chain cannot terminate.
    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    CHECK_THROWS(TlsError, w->sync_wait(TlsStream::connect(std::move(raw), client)));
    w->wait();
}

TEST(tls_no_verify_ok) {
    Fixture fx;
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();

    w->push([](Socket* l, Fixture* fx) -> Task<void> {
        Socket raw = co_await l->accept();
        TlsStream server = co_await TlsStream::accept(std::move(raw), fx->serverConfig());
        CHECK(co_await echoOnce(&server) == "hello");
    }(&listener, &fx));

    TlsConfig client;
    client.verifyPeer = false;
    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    TlsStream stream = w->sync_wait(TlsStream::connect(std::move(raw), client));
    const std::string out = "hello";
    w->sync_wait(stream.write(std::span(out.data(), out.size())));
    std::string in(5, '\0');
    w->sync_wait(stream.readExact(std::span(in.data(), in.size())));
    CHECK(in == "hello");
    w->wait();
}

TEST(tls_expired_fails) {
    Fixture fx;
    fx.leaf = makeLeaf(fx.leafPair, fx.ca, fx.caPair, true);
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();

    w->push([](Socket* l, Fixture* fx) -> Task<void> {
        Socket raw = co_await l->accept();
        try {
            TlsStream server = co_await TlsStream::accept(std::move(raw), fx->serverConfig());
            (void) server;
        }
        catch (const TlsError&) {
        }
    }(&listener, &fx));

    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    CHECK_THROWS(TlsError, w->sync_wait(TlsStream::connect(std::move(raw), fx.clientConfig())));
    w->wait();
}

TEST(h1_over_tls) {
    Fixture fx;
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();

    w->push([](Socket* l, Fixture* fx) -> Task<void> {
        Socket raw = co_await l->accept();
        TlsStream tls = co_await TlsStream::accept(std::move(raw), fx->serverConfig());
        H1Connection conn(std::make_unique<TlsStream>(std::move(tls)));
        HttpRequest req = co_await conn.recvRequest();
        HttpResponse resp;
        resp.body = "secure:" + req.target;
        co_await conn.sendResponse(resp, false, { });
    }(&listener, &fx));

    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    TlsStream tls = w->sync_wait(TlsStream::connect(std::move(raw), fx.clientConfig()));
    H1Connection conn(std::make_unique<TlsStream>(std::move(tls)));
    HttpRequest req;
    req.target = "/tls";
    req.headers.push_back({ "Host", kLoopback });
    req.headers.push_back({ "Connection", "close" });
    w->sync_wait(conn.sendRequest(req));
    HttpResponse r = w->sync_wait(conn.recvResponse());
    CHECK(r.status == 200);
    CHECK(r.body == "secure:/tls");
    w->wait();
}

TEST(tls_psk_resumption) {
    Fixture fx;
    auto cache = std::make_shared<PskCache>();
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    TlsConfig serverCfg = fx.serverConfigWithTickets();

    w->push([](Socket* l, TlsConfig* cfg, Canceller ct) -> Task<void> {
        while (!ct.isTriggered()) {
            Socket raw;
            try {
                raw = co_await l->accept(ct);
            }
            catch (const OperationCanceled&) {
                break;
            }
            try {
                TlsStream server = co_await TlsStream::accept(std::move(raw), *cfg, ct);
                CHECK(co_await echoOnce(&server) == "hello");
            }
            catch (...) {
            }
        }
    }(&listener, &serverCfg, stop.canceller));

    auto roundTrip = [](std::uint16_t port, TlsConfig cfg) -> Task<bool> {
        Socket raw = co_await Socket::connect(kLoopback, port);
        TlsStream client = co_await TlsStream::connect(std::move(raw), std::move(cfg));
        const bool resumed = client.resumed();
        const std::string out = "hello";
        co_await client.write(std::span(out.data(), out.size()));
        std::string in(5, '\0');
        co_await client.readExact(std::span(in.data(), in.size()));
        CHECK(in == "hello");
        client.close();
        co_return resumed;
    };

    TlsConfig first = fx.clientConfig();
    first.pskCache = cache;
    CHECK(w->sync_wait(roundTrip(port, std::move(first))) == false);

    // The ticket arrives post-handshake; wait until the cache holds it.
    for (int i = 0; i < 200 && !cache->load("localhost"); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(!!cache->load("localhost"));

    TlsConfig second = fx.clientConfig();
    second.pskCache = cache;
    CHECK(w->sync_wait(roundTrip(port, std::move(second))) == true);

    stop.trigger();
    w->wait();
}

TEST(tls_psk_fallback_without_ticket_key) {
    Fixture fx;
    auto cache = std::make_shared<PskCache>();
    auto w = std::make_shared<ThreadPooledWorker>(4);

    // First server issues tickets; second has no key: must fall back silently.
    Socket l1 = Socket::bind(kLoopback, 0);
    const std::uint16_t p1 = l1.localPort();
    Socket l2 = Socket::bind(kLoopback, 0);
    const std::uint16_t p2 = l2.localPort();
    CancellerSource stop;
    TlsConfig withTickets = fx.serverConfigWithTickets();
    TlsConfig plain = fx.serverConfig();
    auto serve = [](Socket* l, TlsConfig* cfg, Canceller ct) -> Task<void> {
        while (!ct.isTriggered()) {
            Socket raw;
            try {
                raw = co_await l->accept(ct);
            }
            catch (const OperationCanceled&) {
                break;
            }
            try {
                TlsStream server = co_await TlsStream::accept(std::move(raw), *cfg, ct);
                CHECK(co_await echoOnce(&server) == "hello");
            }
            catch (...) {
            }
        }
    };
    w->push(serve(&l1, &withTickets, stop.canceller));
    w->push(serve(&l2, &plain, stop.canceller));

    auto roundTrip = [&](std::uint16_t port, TlsConfig cfg) -> Task<bool> {
        Socket raw = co_await Socket::connect(kLoopback, port);
        TlsStream client = co_await TlsStream::connect(std::move(raw), std::move(cfg));
        const bool resumed = client.resumed();
        const std::string out = "hello";
        co_await client.write(std::span(out.data(), out.size()));
        std::string in(5, '\0');
        co_await client.readExact(std::span(in.data(), in.size()));
        CHECK(in == "hello");
        client.close();
        co_return resumed;
    };

    TlsConfig first = fx.clientConfig();
    first.pskCache = cache;
    CHECK(w->sync_wait(roundTrip(p1, std::move(first))) == false);
    for (int i = 0; i < 200 && !cache->load("localhost"); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Same cache, server without a ticket key: full handshake, no error.
    TlsConfig second = fx.clientConfig();
    second.pskCache = cache;
    CHECK(w->sync_wait(roundTrip(p2, std::move(second))) == false);

    stop.trigger();
    w->wait();
}

TEST(tls_mutual_success) {
    Fixture fx;
    // Client identity: EKU clientAuth leaf under the same CA.
    auto clientPair = generateKey(cc::EASYM_P256, 256);
    cx::CCert clientLeaf = makeLeaf(clientPair, fx.ca, fx.caPair, false,
        cx::CEkuExtension::OID_CLIENT_AUTH);
    {
        auto priv = clientPair.privateKey;
        checkCert(clientLeaf.privateKey(priv));
    }

    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;

    TlsConfig serverCfg = fx.serverConfig();
    serverCfg.verifyClient = true;
    serverCfg.clientTrustAnchors = { fx.ca };
    w->push([](Socket* l, TlsConfig* cfg, Canceller ct) -> Task<void> {
        Socket raw = co_await l->accept(ct);
        TlsStream server = co_await TlsStream::accept(std::move(raw), *cfg, ct);
        CHECK(server.peerCertificates().size() == 1);
        CHECK(co_await echoOnce(&server) == "hello");
        server.close();
    }(&listener, &serverCfg, stop.canceller));

    TlsConfig client = fx.clientConfig();
    client.clientCertificateChain = { clientLeaf };
    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    TlsStream stream = w->sync_wait(TlsStream::connect(std::move(raw), std::move(client)));
    const std::string out = "hello";
    w->sync_wait(stream.write(std::span(out.data(), out.size())));
    std::string in(5, '\0');
    w->sync_wait(stream.readExact(std::span(in.data(), in.size())));
    CHECK(in == "hello");
    CHECK(!stream.resumed());
    stop.trigger();
    w->wait();
}

TEST(tls_mutual_no_client_cert_fails) {
    Fixture fx;
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;

    TlsConfig serverCfg = fx.serverConfig();
    serverCfg.verifyClient = true;
    serverCfg.clientTrustAnchors = { fx.ca };
    w->push([](Socket* l, TlsConfig* cfg, Canceller ct) -> Task<void> {
        Socket raw = co_await l->accept(ct);
        try {
            TlsStream server = co_await TlsStream::accept(std::move(raw), *cfg, ct);
            (void) server;
        }
        catch (const TlsError&) {
        }
    }(&listener, &serverCfg, stop.canceller));

    // Client has no chain to offer: must fail fast, not hang.
    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    CHECK_THROWS(TlsError, w->sync_wait(TlsStream::connect(std::move(raw), fx.clientConfig())));
    stop.trigger();
    w->wait();
}

TEST(tls_server_sends_hrr_without_key_share) {
    // A ClientHello without a key share gets a well-formed HelloRetryRequest
    // asking for x25519 (RFC 8446 4.1.4), not a bare failure.
    Fixture fx;
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;

    TlsConfig serverCfg = fx.serverConfig();
    w->push([](Socket* l, TlsConfig* cfg, Canceller ct) -> Task<void> {
        Socket raw = co_await l->accept(ct);
        try {
            TlsStream server = co_await TlsStream::accept(std::move(raw), *cfg, ct);
            (void) server;
        }
        catch (...) {
        }
    }(&listener, &serverCfg, stop.canceller));

    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    // Minimal ClientHello: random, empty session, one suite, null compression,
    // versions extension only (no key share).
    std::vector<uint8_t> ch;
    ch.push_back(1);
    ch.insert(ch.end(), { 0, 0, 0 }); // length patched below.
    ch.push_back(0x03);
    ch.push_back(0x03);
    ch.insert(ch.end(), 32, 0x11);
    ch.push_back(0);
    ch.push_back(0);
    ch.push_back(2);
    ch.push_back(0x13);
    ch.push_back(0x01);
    ch.push_back(1);
    ch.push_back(0);
    ch.push_back(0);
    ch.push_back(7); // extensions length
    ch.push_back(0);
    ch.push_back(43); // supported_versions
    ch.push_back(0);
    ch.push_back(3); // extension data length
    ch.push_back(2); // list length
    ch.push_back(3);
    ch.push_back(4); // TLS 1.3
    const uint32_t bodyLen = static_cast<uint32_t>(ch.size() - 4);
    ch[1] = static_cast<uint8_t>(bodyLen >> 16);
    ch[2] = static_cast<uint8_t>(bodyLen >> 8);
    ch[3] = static_cast<uint8_t>(bodyLen);
    std::vector<uint8_t> record = { 22, 3, 3 };
    const uint16_t reclen = static_cast<uint16_t>(ch.size());
    record.push_back(static_cast<uint8_t>(reclen >> 8));
    record.push_back(static_cast<uint8_t>(reclen));
    record.insert(record.end(), ch.begin(), ch.end());
    w->sync_wait(raw.sendAll(std::span(
        reinterpret_cast<const char*>(record.data()), record.size())));

    // Expect one handshake record: ServerHello with the retry magic.
    uint8_t hdr[5];
    w->sync_wait(raw.recvExact(std::span(reinterpret_cast<char*>(hdr), 5)));
    CHECK(hdr[0] == 22);
    const size_t n = size_t { hdr[3] } << 8 | hdr[4];
    std::vector<uint8_t> sh(n, 0);
    w->sync_wait(raw.recvExact(std::span(reinterpret_cast<char*>(sh.data()), n)));
    CHECK(sh[0] == 2); // ServerHello type.
    static const uint8_t kMagic[8] = { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11 };
    // sh = [type(1) | length(3) | legacy_version(2) | random(32) ...]
    CHECK(std::memcmp(sh.data() + 6, kMagic, 8) == 0);
    raw.close();
    stop.trigger();
    w->wait();
}

TEST(tls_client_handles_hrr) {
    // Fake server: HRR once (with cookie), then expect a second ClientHello
    // echoing the cookie and offering no PSK. Client must get past the retry.
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    std::atomic<bool> ch2Ok { false };

    w->push([](Socket* l, std::atomic<bool>* ok) -> Task<void> {
        Socket raw = co_await l->accept();
        auto readRecord = [&](std::vector<uint8_t>& payload) -> Task<void> {
            uint8_t hdr[5];
            co_await raw.recvExact(std::span(reinterpret_cast<char*>(hdr), 5));
            const size_t n = size_t { hdr[3] } << 8 | hdr[4];
            payload.assign(n, 0);
            co_await raw.recvExact(std::span(reinterpret_cast<char*>(payload.data()), n));
        };
        std::vector<uint8_t> ch1;
        co_await readRecord(ch1); // ClientHello, ignored beyond the session id.
        const size_t sessionLen = ch1[4 + 2 + 32];
        std::vector<uint8_t> session(ch1.begin() + 4 + 2 + 32 + 1,
            ch1.begin() + 4 + 2 + 32 + 1 + sessionLen);

        std::vector<uint8_t> hrr;
        hrr.push_back(2);
        hrr.insert(hrr.end(), { 0, 0, 0 }); // length patched below.
        hrr.push_back(0x03);
        hrr.push_back(0x03);
        static const uint8_t kMagic[32] = { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16,
            0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };
        hrr.insert(hrr.end(), std::begin(kMagic), std::end(kMagic));
        hrr.push_back(static_cast<uint8_t>(session.size()));
        hrr.insert(hrr.end(), session.begin(), session.end());
        hrr.push_back(0x13);
        hrr.push_back(0x01);
        hrr.push_back(0);
        std::vector<uint8_t> exts;
        auto put16 = [&](std::vector<uint8_t>& o, uint16_t v) {
            o.push_back(static_cast<uint8_t>(v >> 8));
            o.push_back(static_cast<uint8_t>(v));
        };
        std::vector<uint8_t> v = { 0x03, 0x04 };
        put16(exts, 43);
        put16(exts, 2);
        exts.insert(exts.end(), v.begin(), v.end());
        std::vector<uint8_t> ks = { 0x00, 0x1D };
        put16(exts, 51);
        put16(exts, 2);
        exts.insert(exts.end(), ks.begin(), ks.end());
        const std::string cookieData = "cookie12";
        put16(exts, 44);
        put16(exts, static_cast<uint16_t>(cookieData.size()));
        exts.insert(exts.end(), cookieData.begin(), cookieData.end());
        put16(hrr, static_cast<uint16_t>(exts.size()));
        hrr.insert(hrr.end(), exts.begin(), exts.end());
        const uint32_t hlen = static_cast<uint32_t>(hrr.size() - 4);
        hrr[1] = static_cast<uint8_t>(hlen >> 16);
        hrr[2] = static_cast<uint8_t>(hlen >> 8);
        hrr[3] = static_cast<uint8_t>(hlen);
        std::vector<uint8_t> rec = { 22, 3, 3,
            static_cast<uint8_t>(hrr.size() >> 8), static_cast<uint8_t>(hrr.size()) };
        rec.insert(rec.end(), hrr.begin(), hrr.end());
        co_await raw.sendAll(
            std::span(reinterpret_cast<const char*>(rec.data()), rec.size()));

        // Second flight must be a ClientHello echoing our cookie.
        std::vector<uint8_t> ch2;
        co_await readRecord(ch2);
        const std::string blob(ch2.begin(), ch2.end());
        *ok = ch2.size() > 4 && ch2[0] == 1
            && blob.find("cookie12") != std::string::npos;
        raw.close();
    }(&listener, &ch2Ok));

    // Our client has no anchors here; it must still survive the retry itself
    // and only fail later (no verifiable server flight follows).
    TlsConfig client;
    client.verifyPeer = false;
    Socket raw = w->sync_wait(Socket::connect(kLoopback, port));
    try {
        TlsStream stream = w->sync_wait(TlsStream::connect(std::move(raw), std::move(client)));
        (void) stream;
    }
    catch (const TlsError&) {
        // Expected: the fake server closes after CH2 instead of finishing.
    }
    for (int i = 0; i < 200 && !ch2Ok.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(ch2Ok.load());
    w->wait();
}

TEST_MAIN()
