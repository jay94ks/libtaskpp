// Scratch interop probe (not a test): TLS handshake + HTTP/1.1 against a real
// server. Proves the stack is not merely self-consistent.
#include <taskpp/http/Http.hpp>
#include <taskpp/core/Core.hpp>

#include <cstdio>

using namespace taskpp;
using namespace taskpp::http;
using namespace taskpp::tls;

Task<void> probe() {
    Socket raw = co_await Socket::connect("example.com", 443);
    TlsConfig config;
    config.verifyPeer = false; // handshake + framing only (no roots available).
    config.serverName = "example.com";
    config.alpn = { "http/1.1" };
    TlsStream tls = co_await TlsStream::connect(std::move(raw), config);
    std::printf("negotiated: %s\n", tls.negotiatedAlpn().c_str());

    H1Connection conn(std::make_unique<TlsStream>(std::move(tls)));
    HttpRequest req;
    req.target = "/";
    req.headers.push_back({ "Host", "example.com" });
    req.headers.push_back({ "Connection", "close" });
    co_await conn.sendRequest(req);
    HttpResponse r = co_await conn.recvResponse();
    std::printf("status: %d body-bytes: %zu\n", r.status, r.body.size());
    std::printf("%.120s\n", r.body.bytes().c_str());
}

int main() {
    try {
        Worker::defaultWorker()->sync_wait(probe());
    }
    catch (const std::exception& e) {
        std::printf("probe failed: %s\n", e.what());
        return 1;
    }
    return 0;
}
