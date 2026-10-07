#include "TestHarness.hpp"
#include "TestCerts.hpp"

#include <taskpp/http/Http.hpp>
#include <taskpp/core/Core.hpp>
#include <taskpp/core/WhenAll.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace taskpp;
using namespace taskpp::http;
using namespace taskpp::tls;
using namespace taskpp::http::hpack;
using namespace testcerts;

namespace {

std::vector<uint8_t> hexed(const std::string& hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

} // namespace

// RFC 7541 C.3: indexed header field representation.
TEST(hpack_indexed) {
    Decoder decoder;
    // 0x82 = indexed 2 (:method GET).
    auto fields = decoder.decode(hexed("82"));
    CHECK(fields.size() == 1);
    CHECK(fields[0].name == ":method" && fields[0].value == "GET");
}

// RFC 7541 C.4.1: first request without Huffman coding.
TEST(hpack_first_request_no_huffman) {
    Decoder decoder;
    // 8286 8441 8cf1e3c2e5f23a6ba0ab90f4ff
    auto fields = decoder.decode(hexed("828684418cf1e3c2e5f23a6ba0ab90f4ff"));
    CHECK(fields.size() == 4);
    CHECK(fields[0].name == ":method" && fields[0].value == "GET");
    CHECK(fields[1].name == ":scheme" && fields[1].value == "http");
    CHECK(fields[2].name == ":path" && fields[2].value == "/");
    CHECK(fields[3].name == ":authority" && fields[3].value == "www.example.com");
}

// Second request: indexed :authority (dynamic table) + literal cache-control.
// Vector produced by python-hpack (a second implementation, not memory).
TEST(hpack_second_request) {
    Decoder decoder;
    decoder.decode(hexed("828684418cf1e3c2e5f23a6ba0ab90f4ff"));
    auto fields = decoder.decode(hexed("828684be5886a8eb10649cbf"));
    CHECK(fields.size() == 5);
    CHECK(fields[0].value == "GET");
    CHECK(fields[1].value == "http");
    CHECK(fields[2].value == "/");
    CHECK(fields[3].name == ":authority" && fields[3].value == "www.example.com");
    CHECK(fields[4].name == "cache-control" && fields[4].value == "no-cache");
}

// Huffman-heavy response block from python-hpack (dynamic table + huffman).
TEST(hpack_huffman_response) {
    Decoder decoder;
    auto fields = decoder.decode(
        hexed("884088f2b14939d6ac699f856272d141ff408af2b14939d6a4a99cf27f83c5837f408825a849e95ba97d7f8925a849e95bb8e8b4bf"));
    CHECK(fields.size() == 4);
    CHECK(fields[0].name == ":status" && fields[0].value == "200");
    CHECK(fields[1].name == "x-echo-path" && fields[1].value == "/hello");
    CHECK(fields[2].name == "x-echo-method" && fields[2].value == "GET");
    CHECK(fields[3].name == "custom-key" && fields[3].value == "custom-value");
}

// Encoder round-trips through the decoder (dynamic table included).
TEST(hpack_encode_round_trip) {
    Encoder encoder;
    Decoder decoder;
    std::vector<HeaderField> first = {
        { ":method", "GET" },
        { ":scheme", "https" },
        { ":path", "/index.html" },
        { ":authority", "example.com" },
        { "custom-key", "custom-value" },
    };
    auto once = decoder.decode(encoder.encode(first));
    CHECK(once.size() == first.size());
    for (size_t i = 0; i < first.size(); ++i) {
        CHECK(once[i].name == first[i].name && once[i].value == first[i].value);
    }
    std::vector<HeaderField> second = {
        { ":method", "GET" },
        { ":scheme", "https" },
        { ":path", "/index.html" },
        { ":authority", "example.com" },
        { "custom-key", "custom-value2" },
    };
    auto twice = decoder.decode(encoder.encode(second));
    CHECK(twice.size() == second.size());
    for (size_t i = 0; i < second.size(); ++i) {
        CHECK(twice[i].name == second[i].name && twice[i].value == second[i].value);
    }
}

TEST(hpack_rejects_bad_index) {
    Decoder decoder;
    CHECK_THROWS(HpackError, decoder.decode(hexed("ff"))); // indexed 127: out of range.
}

namespace {

Task<H2Response> echoHandler(H2Request req) {
    H2Response res;
    res.headers.push_back({ "x-echo-path", req.path });
    res.headers.push_back({ "x-echo-method", req.method });
    res.body = "h2:" + req.body.bytes();
    co_return res;
}

Task<void> runH2c(Socket* listener, H2Handler handler, Canceller canceller) {
    co_await H2Server::serveH2c(std::move(*listener), std::move(handler), { }, std::move(canceller));
}

std::string urlFor(Socket* listener, const std::string& path) {
    return "http://" + std::string(kLoopback) + ":" + std::to_string(listener->localPort()) + path;
}

} // namespace

TEST(h2c_get_round_trip) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::string url = urlFor(&listener, "/hello");
    CancellerSource stop;
    w->push(runH2c(&listener, echoHandler, stop.canceller));

    H2Response r = w->sync_wait(H2Client::get(url));
    CHECK(r.status == 200);
    CHECK(r.body == "h2:");
    CHECK(headerValue(r.headers, "x-echo-path") == "/hello");
    CHECK(headerValue(r.headers, "x-echo-method") == "GET");
    stop.trigger();
    w->wait();
}

TEST(h2c_post_body_round_trip) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::string url = urlFor(&listener, "/post");
    CancellerSource stop;
    w->push(runH2c(&listener, echoHandler, stop.canceller));

    H2Response r = w->sync_wait(H2Client::post(url, "payload", "text/plain"));
    CHECK(r.status == 200);
    CHECK(r.body == "h2:payload");
    stop.trigger();
    w->wait();
}

TEST(h2c_many_streams_sequential) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    w->push(runH2c(&listener, echoHandler, stop.canceller));

    // Several connections in flight at once (server multiplexes streams).
    std::atomic<int> ok { 0 };
    for (int i = 0; i < 8; ++i) {
        w->push([](std::uint16_t p, std::atomic<int>* ok) -> Task<void> {
            const std::string url = "http://" + std::string(kLoopback) + ":" + std::to_string(p) + "/x";
            H2Response r = co_await H2Client::get(url);
            if (r.status == 200 && r.body == "h2:") {
                ok->fetch_add(1);
            }
        }(port, &ok));
    }
    for (int i = 0; i < 200 && ok.load() < 8; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(ok.load() == 8);
    stop.trigger();
    w->wait();
}

TEST(h2_tls_round_trip) {
    testcerts::Fixture fx;
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;

    w->push([](Socket* l, testcerts::Fixture* fx, Canceller ct) -> Task<void> {
        co_await H2Server::serveTls(std::move(*l), fx->serverConfig(), echoHandler, { }, ct);
    }(&listener, &fx, stop.canceller));

    const std::string url = "https://localhost:" + std::to_string(port) + "/secure";
    H2Response r = w->sync_wait(H2Client::request("GET", url, { }, { }, fx.clientConfig()));
    CHECK(r.status == 200);
    CHECK(r.body == "h2:");
    CHECK(headerValue(r.headers, "x-echo-path") == "/secure");
    stop.trigger();
    w->wait();
}

TEST(h2c_concurrent_requests_one_connection) {
    // A single connection now multiplexes: several requests are in flight at
    // once instead of queueing behind a mutex. The handlers park until all six
    // have arrived, which can only happen if they really overlap.
    constexpr int kParallel = 6;
    constexpr std::size_t kParallelSlots = kParallel;
    auto w = std::make_shared<ThreadPooledWorker>(8);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    std::atomic<int> arrived { 0 };
    // One token per request: every handler parks until the test has seen all
    // six arrive, which can only happen if they really are concurrent.
    Channel<char> gate { kParallelSlots };
    w->push(runH2c(&listener, [&arrived, &gate](H2Request req) -> Task<H2Response> {
        arrived.fetch_add(1);
        co_await gate.receive({ });
        H2Response r;
        r.body = req.path;
        co_return r;
    }, stop.canceller));

    Socket socket = w->sync_wait(Socket::connect(kLoopback, port));
    H2Connection conn = w->sync_wait(H2Connection::connect(
        std::make_unique<SocketStream>(std::move(socket))));
    CHECK(conn.maxConcurrentStreams() >= 6);

    std::atomic<int> ok { 0 };
    for (int i = 0; i < kParallel; ++i) {
        w->push([](H2Connection* c, int i, std::atomic<int>* ok) -> Task<void> {
            H2Request req;
            req.authority = "localhost";
            req.path = "/p" + std::to_string(i);
            try {
                H2Response r = co_await c->request(std::move(req));
                if (r.status == 200 && r.body == "/p" + std::to_string(i)) {
                    ok->fetch_add(1);
                }
            }
            catch (const std::exception&) {
            }
        }(&conn, i, &ok));
    }

    for (int i = 0; i < 600 && arrived.load() < kParallel; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(arrived.load() == kParallel); // all six really were concurrent
    for (int i = 0; i < kParallel; ++i) {
        CHECK(gate.trySend(1)); // release the parked handlers
    }
    for (int i = 0; i < 600 && ok.load() < kParallel; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(ok.load() == kParallel);
    conn.close();
    stop.trigger();
    w->wait();
}

TEST(h2_client_declines_push) {
    // The server sends PUSH_PROMISE; the client must reset the promised stream
    // and keep the original request working (RFC 9113 8.4).
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    w->push(runH2c(&listener, echoHandler, stop.canceller));

    Socket socket = w->sync_wait(Socket::connect(kLoopback, port));
    H2Connection conn = w->sync_wait(H2Connection::connect(
        std::make_unique<SocketStream>(std::move(socket))));
    H2Request req;
    req.authority = "localhost";
    req.path = "/";
    H2Response r = w->sync_wait(conn.request(std::move(req)));
    CHECK(r.status == 200);
    CHECK(r.body == "h2:");
    // ENABLE_PUSH = 0 was advertised, so a well-behaved server pushes nothing.
    CHECK(conn.pushPromises().empty());
    conn.close();
    stop.trigger();
    w->wait();
}

TEST(h2_goaway_stops_new_requests) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    w->push(runH2c(&listener, echoHandler, stop.canceller));

    Socket socket = w->sync_wait(Socket::connect(kLoopback, port));
    H2Connection conn = w->sync_wait(H2Connection::connect(
        std::make_unique<SocketStream>(std::move(socket))));
    conn.close(); // RST the socket; the pump notices and drains.
    for (int i = 0; i < 200 && !conn.goaway(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    // Closing is not GOAWAY, but no further request may be issued.
    CHECK_THROWS(H2Error, w->sync_wait(conn.request(H2Request { })));
    stop.trigger();
    w->wait();
}

TEST_MAIN()
