// Coroutine TCP echo: one server connection, one client round trip.

#include <taskpp/taskpp.hpp>

#include <cstdio>
#include <string>

using namespace taskpp;

Task<void> runServer(Socket* listener) {
    Socket conn = co_await listener->accept();
    std::string buffer(5, '\0');
    co_await conn.recvExact(std::span(buffer.data(), buffer.size()));
    std::printf("server received: %s\n", buffer.c_str());
    co_await conn.sendAll(std::span(buffer.data(), buffer.size()));
}

int main() {
    auto worker = Worker::defaultWorker();
    Socket listener = Socket::bind("127.0.0.1", 0);
    worker->push(runServer(&listener));

    worker->sync_wait([](Socket* l) -> Task<void> {
        Socket client = co_await Socket::connect("127.0.0.1", l->localPort());
        const std::string out = "hello";
        co_await client.sendAll(std::span(out.data(), out.size()));
        std::string in(5, '\0');
        co_await client.recvExact(std::span(in.data(), in.size()));
        std::printf("client received: %s\n", in.c_str());
    }(&listener));

    worker->wait();
    return 0;
}
