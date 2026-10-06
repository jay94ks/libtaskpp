#include "TestHarness.hpp"

#include <taskpp/socket/Socket.hpp>
#include <taskpp/socket/Dns.hpp>
#include <taskpp/core/Core.hpp>
#include <taskpp/core/WhenAll.hpp>

#include <atomic>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

using namespace taskpp;

namespace {

constexpr const char* kLoopback = "127.0.0.1";

Task<void> echoServer(Socket* listener, int count) {
    for (int i = 0; i < count; ++i) {
        Socket conn = co_await listener->accept();
        std::vector<char> buffer(256);
        co_await conn.recvExact(std::span(buffer.data(), 5));
        co_await conn.sendAll(std::span(buffer.data(), 5));
    }
    co_return;
}

Task<std::string> talk(Socket* client) {
    const std::string out = "hello";
    co_await client->sendAll(std::span(out.data(), out.size()));
    std::string in(5, '\0');
    co_await client->recvExact(std::span(in.data(), in.size()));
    co_return in;
}

Task<Socket> connectTo(Socket* listener) {
    co_return co_await Socket::connect(kLoopback, listener->localPort());
}

Task<void> talkAndCount(const char* host, std::uint16_t port, std::atomic<int>* ok) {
    Socket client = co_await Socket::connect(host, port);
    if (co_await talk(&client) == "hello") {
        ok->fetch_add(1);
    }
}

} // namespace

// ------------------------------------------------------------------ address

TEST(address_numeric_factories) {
    const SocketAddress v4 = SocketAddress::loopback(80);
    CHECK(v4.family() == AddressFamily::IPv4);
    CHECK(v4.host() == "127.0.0.1");
    CHECK(v4.port() == 80);
    CHECK(v4.toString() == "127.0.0.1:80");

    const SocketAddress v6 = SocketAddress::loopback(443, true);
    CHECK(v6.family() == AddressFamily::IPv6);
    CHECK(v6.host() == "::1");
    CHECK(v6.port() == 443);
    CHECK(v6.toString() == "[::1]:443");

    CHECK(SocketAddress::wildcard(0).host() == "0.0.0.0");
    CHECK(SocketAddress().empty());
    CHECK(!(v4 == v6));
    CHECK(v4 == SocketAddress::fromIp("127.0.0.1", 80));
    CHECK_THROWS(std::invalid_argument, SocketAddress::fromIp("not-an-ip", 80));
}

TEST(address_resolve_numeric) {
    const auto addrs = Dns::resolveSync("127.0.0.1", 8080, SocketType::Tcp);
    CHECK(!addrs.empty());
    CHECK(addrs.front().host() == "127.0.0.1");
    CHECK(addrs.front().port() == 8080);
}

// ------------------------------------------------------------------ DNS

TEST(dns_resolve_numeric_skips_network) {
    auto w = std::make_shared<ThreadedWorker>();
    // Numeric literals resolve inline: exactly one address, no DNS traffic.
    auto v4 = w->sync_wait(Dns::resolve("127.0.0.1", 80, SocketType::Tcp));
    CHECK(v4.size() == 1);
    CHECK(v4.front().toString() == "127.0.0.1:80");

    auto v6 = w->sync_wait(Dns::resolve("::1", 443, SocketType::Udp));
    CHECK(v6.size() == 1);
    CHECK(v6.front().toString() == "[::1]:443");
}

TEST(dns_lookup_localhost) {
    auto w = std::make_shared<ThreadedWorker>();
    // "localhost" goes through the resolver worker (hosts file: no network needed).
    auto records = w->sync_wait(Dns::lookup("localhost"));
    CHECK(!records.empty());
}

TEST(dns_invalid_host_throws) {
    auto w = std::make_shared<ThreadedWorker>();
    CHECK_THROWS(std::runtime_error, w->sync_wait(Dns::resolve("invalid.invalid", 80)));
}

TEST(dns_empty_host_is_wildcard) {
    auto w = std::make_shared<ThreadedWorker>();
    const auto addrs = w->sync_wait(Dns::resolve("", 8080));
    CHECK(!addrs.empty());
    CHECK(addrs.front().host() == "0.0.0.0");
    CHECK(addrs.front().port() == 8080);
}

TEST(dns_canceled_throws) {
    auto w = std::make_shared<ThreadedWorker>();
    CancellerSource cs;
    cs.trigger();
    CHECK_THROWS(OperationCanceled, w->sync_wait(Dns::resolve("localhost", 80, SocketType::Tcp, cs.canceller)));
    CHECK_THROWS(OperationCanceled, w->sync_wait(Dns::lookup("localhost", cs.canceller)));
}

TEST(dns_resumes_on_caller_worker) {
    auto w = std::make_shared<ThreadedWorker>();
    const bool same = w->sync_wait([]() -> Task<bool> {
        auto before = Worker::currentWorker();
        co_await Dns::resolve("localhost", 80);
        co_return before && before == Worker::currentWorker();
    }());
    CHECK(same);
}

// ------------------------------------------------------------------ TCP

TEST(tcp_echo_full) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    w->push(echoServer(&listener, 1));

    Socket client = w->sync_wait(connectTo(&listener));
    CHECK(w->sync_wait(talk(&client)) == "hello");
    w->wait();
}

TEST(tcp_connect_hostname) {
    // End to end through Dns (localhost may resolve to ::1 first: fallback).
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind("localhost", 0);
    w->push(echoServer(&listener, 1));

    Socket client = w->sync_wait(Socket::connect("localhost", listener.localPort()));
    CHECK(w->sync_wait(talk(&client)) == "hello");
    w->wait();
}

TEST(tcp_connect_address_overload) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(SocketAddress::loopback(0));
    w->push(echoServer(&listener, 1));

    const SocketAddress peer = SocketAddress::loopback(listener.localPort());
    Socket client = w->sync_wait(Socket::connect(peer));
    CHECK(w->sync_wait(talk(&client)) == "hello");
    w->wait();
}

TEST(tcp_large_transfer_integrity) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);

    w->push([](Socket* l) -> Task<void> {
        Socket conn = co_await l->accept();
        std::vector<char> buffer(1 << 20);
        co_await conn.recvExact(std::span(buffer.data(), buffer.size()));
        unsigned sum = 0;
        for (unsigned char c : buffer) {
            sum += c;
        }
        char reply[4];
        reply[0] = static_cast<char>(sum & 0xFF);
        reply[1] = static_cast<char>((sum >> 8) & 0xFF);
        reply[2] = static_cast<char>((sum >> 16) & 0xFF);
        reply[3] = static_cast<char>((sum >> 24) & 0xFF);
        co_await conn.sendAll(std::span(reply, 4));
    }(&listener));

    Socket client = w->sync_wait(connectTo(&listener));
    std::vector<char> payload(1 << 20);
    std::iota(payload.begin(), payload.end(), 0);
    unsigned expected = 0;
    for (unsigned char c : payload) {
        expected += c;
    }
    w->sync_wait(client.sendAll(std::span(payload.data(), payload.size())));
    char reply[4] = { };
    w->sync_wait(client.recvExact(std::span(reply, 4)));
    const unsigned got = static_cast<unsigned char>(reply[0])
        | (static_cast<unsigned>(static_cast<unsigned char>(reply[1])) << 8)
        | (static_cast<unsigned>(static_cast<unsigned char>(reply[2])) << 16)
        | (static_cast<unsigned>(static_cast<unsigned char>(reply[3])) << 24);
    CHECK(got == expected);
    w->wait();
}

TEST(tcp_connect_refused) {
    // Grab an ephemeral port, release it, then refuse on it.
    std::uint16_t port;
    {
        Socket tmp = Socket::bind(kLoopback, 0);
        port = tmp.localPort();
    }
    auto w = std::make_shared<ThreadedWorker>();
    CHECK_THROWS(std::system_error, w->sync_wait(Socket::connect(kLoopback, port)));
}

TEST(tcp_recv_eof) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    w->push([](Socket* l) -> Task<void> {
        Socket conn = co_await l->accept();
        std::vector<char> buffer(8, '\0');
        const std::size_t n = co_await conn.recvSome(std::span(buffer.data(), buffer.size()));
        CHECK(n == 0); // orderly shutdown reads as EOF.
        CHECK_THROWS(SocketClosed, co_await conn.recvExact(std::span(buffer.data(), buffer.size())));
    }(&listener));

    {
        Socket client = w->sync_wait(connectTo(&listener));
        client.shutdown(ShutdownHow::Write);
    }
    w->wait();
}

TEST(tcp_accept_timeout) {
    auto w = std::make_shared<ThreadedWorker>();
    Socket listener = Socket::bind(kLoopback, 0);
    CHECK_THROWS(Timeout, w->sync_wait(withTimeout(listener.accept(), TimeSpan::fromMilliseconds(50))));
}

TEST(tcp_recv_timeout) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    w->push([](Socket* l) -> Task<void> {
        Socket conn = co_await l->accept();
        std::vector<char> buffer(8, '\0');
        CHECK_THROWS(Timeout,
            co_await withTimeout(conn.recvExact(std::span(buffer.data(), buffer.size())),
                TimeSpan::fromMilliseconds(50)));
    }(&listener));

    Socket client = w->sync_wait(connectTo(&listener));
    (void) client;
    w->wait();
}

TEST(tcp_many_clients) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    constexpr int kClients = 16;
    w->push(echoServer(&listener, kClients));

    std::atomic<int> ok { 0 };
    for (int i = 0; i < kClients; ++i) {
        w->push(talkAndCount(kLoopback, listener.localPort(), &ok));
    }
    w->wait();
    CHECK(ok.load() == kClients);
}

// ------------------------------------------------------------------ UDP

TEST(udp_echo) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket a = Socket::bind(kLoopback, 0, SocketType::Udp);
    Socket b = Socket::bind(kLoopback, 0, SocketType::Udp);

    const std::string out = "ping";
    w->sync_wait(a.sendTo(std::span(out.data(), out.size()), kLoopback, b.localPort()));

    std::string in(8, '\0');
    auto [n, from] = w->sync_wait(b.recvFrom(std::span(in.data(), in.size())));
    CHECK(n == 4);
    CHECK(std::string(in.data(), n) == "ping");
    CHECK(from.port == a.localPort());
}

TEST(udp_sendTo_address_overload) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket a = Socket::bind(SocketAddress::loopback(0), SocketType::Udp);
    Socket b = Socket::bind(SocketAddress::loopback(0), SocketType::Udp);

    const std::string out = "pong";
    const SocketAddress peer = SocketAddress::loopback(b.localPort());
    w->sync_wait(a.sendTo(std::span(out.data(), out.size()), peer));

    std::string in(8, '\0');
    auto [n, from] = w->sync_wait(b.recvFrom(std::span(in.data(), in.size())));
    CHECK(n == 4);
    CHECK(from.host == "127.0.0.1");
}

TEST(udp_recv_timeout) {
    auto w = std::make_shared<ThreadedWorker>();
    Socket a = Socket::bind(kLoopback, 0, SocketType::Udp);
    std::string buffer(8, '\0');
    CHECK_THROWS(Timeout,
        w->sync_wait(withTimeout(a.recvFrom(std::span(buffer.data(), buffer.size())),
            TimeSpan::fromMilliseconds(50))));
}

TEST(udp_self_send_receive) {
    // Datagram send/recv through the unified Socket (no stream involved).
    auto w = std::make_shared<ThreadedWorker>();
    Socket ch = Socket::bind(kLoopback, 0, SocketType::Udp);
    const std::uint16_t port = ch.localPort();
    w->sync_wait(ch.sendTo(std::span("x", 1), kLoopback, port));

    std::string buffer(8, '\0');
    auto [n, from] = w->sync_wait(ch.recvFrom(std::span(buffer.data(), buffer.size())));
    CHECK(n == 1);
    CHECK(from.port == port);
}

TEST_MAIN()
