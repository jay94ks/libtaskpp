#include "TestHarness.hpp"

#include <taskpp/http/Http.hpp>
#include <taskpp/core/Core.hpp>
#include <taskpp/core/WhenAll.hpp>

#include <atomic>
#include <string>
#include <vector>

using namespace taskpp;
using namespace taskpp::http;

namespace {

constexpr const char* kLoopback = "127.0.0.1";

Task<HttpResponse> echoHandler(HttpRequest request) {
    HttpResponse response;
    response.body = "echo:" + request.target + ":" + request.body.bytes();
    co_return response;
}

Task<void> runServer(Socket* listener, H1Handler handler, Canceller canceller) {
    H1Server server(std::move(*listener));
    co_await server.serve(std::move(handler), std::move(canceller));
}

std::string urlFor(Socket* listener, const std::string& path) {
    return "http://" + std::string(kLoopback) + ":" + std::to_string(listener->localPort()) + path;
}

Task<HttpResponse> throwingHandler(HttpRequest) {
    throw std::runtime_error("boom");
    co_return HttpResponse();
}

} // namespace

TEST(url_parse) {
    Url u = Url::parse("http://example.com/a/b?x=1");
    CHECK(u.scheme == "http" && u.host == "example.com" && u.port == 80 && u.path == "/a/b?x=1");
    Url s = Url::parse("https://example.com:8443/");
    CHECK(s.scheme == "https" && s.port == 8443 && s.path == "/");
    Url bare = Url::parse("http://example.com");
    CHECK(bare.path == "/");
    CHECK_THROWS(std::invalid_argument, Url::parse("notaurl"));
    CHECK_THROWS(std::invalid_argument, Url::parse("ftp://example.com/"));
}

TEST(reason_phrases) {
    CHECK(reasonPhrase(200) == "OK");
    CHECK(reasonPhrase(404) == "Not Found");
    CHECK(reasonPhrase(500) == "Internal Server Error");
    CHECK(!reasonPhrase(999).empty());
}

TEST(get_round_trip) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::string url = urlFor(&listener, "/hello");
    CancellerSource stop;
    w->push(runServer(&listener, echoHandler, stop.canceller));

    HttpResponse r = w->sync_wait(H1Client::get(url));
    CHECK(r.status == 200);
    CHECK(r.body == "echo:/hello:");
    stop.trigger();
    w->wait();
}

TEST(post_body_round_trip) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::string url = urlFor(&listener, "/post");
    CancellerSource stop;
    w->push(runServer(&listener, echoHandler, stop.canceller));

    HttpResponse r = w->sync_wait(H1Client::post(url, "payload", "text/plain"));
    CHECK(r.status == 200);
    CHECK(r.body == "echo:/post:payload");
    CHECK(headerValue(r.headers, "content-length") == std::to_string(r.body.size()));
    stop.trigger();
    w->wait();
}

TEST(status_404_from_handler) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::string url = urlFor(&listener, "/missing");
    CancellerSource stop;
    w->push(runServer(&listener, [](HttpRequest) -> Task<HttpResponse> {
        HttpResponse r;
        r.status = 404;
        r.body = "nope";
        co_return r;
    }, stop.canceller));

    HttpResponse r = w->sync_wait(H1Client::get(url));
    CHECK(r.status == 404);
    CHECK(r.body == "nope");
    stop.trigger();
    w->wait();
}

TEST(handler_throw_becomes_500) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::string url = urlFor(&listener, "/boom");
    CancellerSource stop;
    w->push(runServer(&listener, throwingHandler, stop.canceller));

    HttpResponse r = w->sync_wait(H1Client::get(url));
    CHECK(r.status == 500);
    stop.trigger();
    w->wait();
}

TEST(keep_alive_sequential_requests) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    std::atomic<int> hits { 0 };
    CancellerSource stop;
    w->push(runServer(&listener, [&](HttpRequest) -> Task<HttpResponse> {
        hits.fetch_add(1);
        HttpResponse r;
        r.body = "ok";
        co_return r;
    }, stop.canceller));

    // One connection, two sequential exchanges.
    Socket socket = w->sync_wait(Socket::connect(kLoopback, port));
    H1Connection conn(std::make_unique<SocketStream>(std::move(socket)));
    for (int i = 0; i < 2; ++i) {
        HttpRequest req;
        req.target = "/";
        req.headers.push_back({ "Host", kLoopback });
        w->sync_wait(conn.sendRequest(req));
        HttpResponse r = w->sync_wait(conn.recvResponse());
        CHECK(r.status == 200 && r.body == "ok");
        CHECK(conn.keepAlive());
    }
    conn.close();
    stop.trigger();
    w->wait();
    CHECK(hits.load() == 2);
}

TEST(chunked_response_decoded) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();

    // Raw socket server speaking chunked encoding by hand.
    w->push([](Socket* l) -> Task<void> {
        Socket conn = co_await l->accept();
        char head[512];
        std::string got;
        while (got.find("\r\n\r\n") == std::string::npos) {
            const std::size_t n = co_await conn.recvSome(std::span(head, sizeof(head)));
            if (n == 0) {
                co_return;
            }
            got.append(head, n);
        }
        const std::string out = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        co_await conn.sendAll(std::span(out.data(), out.size()));
    }(&listener));

    Socket socket = w->sync_wait(Socket::connect(kLoopback, port));
    H1Connection conn(std::make_unique<SocketStream>(std::move(socket)));
    HttpRequest req;
    req.target = "/";
    req.headers.push_back({ "Host", kLoopback });
    req.headers.push_back({ "Connection", "close" });
    w->sync_wait(conn.sendRequest(req));
    HttpResponse r = w->sync_wait(conn.recvResponse());
    CHECK(r.status == 200);
    CHECK(r.body == "hello world");
    w->wait();
}

TEST(head_has_no_body) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::string url = urlFor(&listener, "/h");
    CancellerSource stop;
    w->push(runServer(&listener, echoHandler, stop.canceller));

    HttpResponse r = w->sync_wait(H1Client::request("HEAD", url));
    CHECK(r.status == 200);
    CHECK(r.body.empty());
    stop.trigger();
    w->wait();
}

TEST(expect_100_continue_round_trip) {
    // The client offers Expect: 100-continue; the server defers the body,
    // accepts, and the body arrives in full.
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    std::atomic<int> hits { 0 };
    CancellerSource stop;
    w->push(runServer(&listener, [&](HttpRequest req) -> Task<HttpResponse> {
        hits.fetch_add(1);
        HttpResponse r;
        r.body = "got:" + req.body.bytes();
        co_return r;
    }, stop.canceller));

    Socket socket = w->sync_wait(Socket::connect(kLoopback, port));
    H1Connection conn(std::make_unique<SocketStream>(std::move(socket)));
    HttpRequest req;
    req.method = "POST";
    req.target = "/upload";
    req.headers.push_back({ "Host", kLoopback });
    req.headers.push_back({ "Expect", "100-continue" });
    req.body = "payload";
    w->sync_wait(conn.sendRequest(req));
    HttpResponse r = w->sync_wait(conn.recvResponse());
    CHECK(r.status == 200);
    CHECK(r.body == "got:payload");
    // The interim response is recorded, the final one is what came back.
    CHECK(conn.interimResponses().size() == 1);
    CHECK(conn.interimResponses().front().status == 100);
    conn.close();
    stop.trigger();
    w->wait();
    CHECK(hits.load() == 1);
}

TEST(expect_100_continue_rejected) {
    // Turning the expectation down answers 417 and never reads the body.
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    H1Server server(std::move(listener));
    std::atomic<bool> handlerRan { false };
    w->push([](H1Server* s, std::atomic<bool>* ran, Canceller ct) -> Task<void> {
        co_await s->serve([ran](HttpRequest) -> Task<HttpResponse> {
            ran->store(true);
            co_return HttpResponse();
        }, std::move(ct), [](const HttpRequest&) -> std::optional<HttpResponse> {
            HttpResponse nope;
            nope.status = 417;
            nope.body = "nope";
            return nope;
        });
    }(&server, &handlerRan, stop.canceller));

    Socket socket = w->sync_wait(Socket::connect(kLoopback, port));
    H1Connection conn(std::make_unique<SocketStream>(std::move(socket)));
    HttpRequest req;
    req.method = "POST";
    req.target = "/upload";
    req.headers.push_back({ "Host", kLoopback });
    req.headers.push_back({ "Expect", "100-continue" });
    req.body = "payload";
    w->sync_wait(conn.sendRequest(req));
    HttpResponse r = w->sync_wait(conn.recvResponse());
    CHECK(r.status == 417);
    CHECK(r.body == "nope");
    // Nothing interim: the rejection is the final response.
    CHECK(conn.interimResponses().empty());
    conn.close();
    stop.trigger();
    w->wait();
    CHECK(!handlerRan.load());
}

TEST(interim_responses_are_skipped) {
    // A raw server that sends 103 Early Hints then the real response.
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    w->push([](Socket* l, CancellerSource* done) -> Task<void> {
        Socket conn = co_await l->accept();
        const std::string raw =
            "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        co_await conn.sendAll(std::span(raw.data(), raw.size()));
        conn.shutdown(ShutdownHow::Write);
        // Content-Length already ends the message, so there is no reason to
        // hang up early: closing now can reset away bytes the client has not
        // read yet (Windows does exactly that). Park until the test is done.
        while (!done->canceller.isTriggered()) {
            Channel<char> park { 1 };
            try {
                co_await park.receive(done->canceller);
            }
            catch (const OperationCanceled&) {
                break;
            }
        }
    }(&listener, &stop));

    Socket socket = w->sync_wait(Socket::connect(kLoopback, port));
    H1Connection conn(std::make_unique<SocketStream>(std::move(socket)));
    HttpRequest req;
    req.target = "/";
    req.headers.push_back({ "Host", kLoopback });
    w->sync_wait(conn.sendRequest(req));
    HttpResponse r = w->sync_wait(conn.recvResponse());
    CHECK(r.status == 200 && r.body == "hi");
    CHECK(conn.interimResponses().size() == 1);
    CHECK(conn.interimResponses().front().status == 103);
    conn.close();
    stop.trigger();
    w->wait();
}

// ------------------------------------------------------------- body codecs

TEST(body_media_type) {
    HttpResponse r;
    r.headers.push_back({ "Content-Type", "Application/JSON; charset=\"utf-8\"" });
    const MediaType type = r.mediaType();
    CHECK(type.is("application", "json"));
    CHECK(type.param("charset") == "utf-8");
    CHECK(type.param("missing").empty());
    CHECK(r.isMediaType("application", "json"));

    const MediaType boundary = MediaType::parse("multipart/form-data; boundary=--abc--");
    CHECK(boundary.is("multipart", "form-data"));
    CHECK(boundary.param("boundary") == "--abc--");
    // Round-trips through serialization.
    CHECK(MediaType::parse(boundary.str()).param("boundary") == "--abc--");

    CHECK(!MediaType::parse("garbage").valid());
    HttpResponse none;
    CHECK(!none.mediaType().valid());
}

TEST(body_json_round_trip) {
    HttpResponse r;
    Json doc = Json::object();
    doc["name"] = "taskpp";
    doc["count"] = 7;
    doc["ratio"] = 0.5;
    doc["ok"] = true;
    doc["tags"] = Json::array();
    doc["tags"].push_back("a");
    doc["tags"].push_back("b");
    doc["nested"] = Json::object();
    doc["nested"]["deep"] = Json::parse(R"({"k":[1,2,3]})");
    r.setJson(doc);

    CHECK(r.isMediaType("application", "json"));
    // Object keys are sorted, so the wire form is deterministic.
    CHECK(r.body == R"({"count":7,"name":"taskpp","nested":{"deep":{"k":[1,2,3]}},"ok":true,"ratio":0.5,"tags":["a","b"]})");

    const Json back = Worker::defaultWorker()->sync_wait(r.toJson());
    CHECK(back["name"].asString() == "taskpp");
    CHECK(back["count"].asInt() == 7);
    CHECK(back["count"].isInteger());
    CHECK(back["ratio"].asNumber() == 0.5);
    CHECK(back["ok"].asBool());
    CHECK(back["tags"].size() == 2);
    CHECK(back["tags"].at(1).asString() == "b");
    CHECK(back["nested"]["deep"]["k"].size() == 3);
    CHECK(back["missing"].isNull());
    CHECK(back.contains("name"));
    CHECK(!back.contains("nope"));

    // Pretty printing stays parseable.
    HttpResponse pretty;
    pretty.setJson(doc, 2);
    CHECK(Worker::defaultWorker()->sync_wait(pretty.toJson()) == doc);
}

TEST(json_parser_rejects_garbage) {
    CHECK_THROWS(JsonError, Json::parse("{"));
    CHECK_THROWS(JsonError, Json::parse("[1,]"));
    CHECK_THROWS(JsonError, Json::parse("{\"a\":}"));
    CHECK_THROWS(JsonError, Json::parse("nul"));
    CHECK_THROWS(JsonError, Json::parse("01"));
    CHECK_THROWS(JsonError, Json::parse("\"unterminated"));
    CHECK_THROWS(JsonError, Json::parse("[1] junk"));
    CHECK_THROWS(JsonError, Json::parse("\"\\q\""));
    CHECK(!Json::tryParse("{").has_value());
    CHECK(Json::tryParse("{}").has_value());

    // Escapes, surrogate pairs and round-tripping.
    const std::string text = "\"a\\u00e9\\n\\t\\\"\\ud83d\\ude00\"";
    const Json parsed = Json::parse(text);
    CHECK(parsed.asString().size() == 10);
    CHECK(parsed.asString().compare(6, 4, "\xf0\x9f\x98\x80") == 0); // U+1F600
    CHECK(Json::parse(parsed.dump()) == parsed);
    CHECK(Json::parse("\"A\\u00e9\"").asString() == "A\xC3\xA9");
    CHECK(Json::parse(R"([1,-2,3.5,1e3,-1.5e-2])").size() == 5);
    CHECK(Json::parse(R"({"a":{"b":{"c":1}}})")["a"]["b"]["c"].asInt() == 1);
    CHECK(Json::parse("{}").dump() == "{}");
    CHECK(Json::parse("[]").dump() == "[]");
    CHECK(Json::parse("9223372036854775807").asInt() == 9223372036854775807LL);
}

TEST(url_encoded_form_round_trip) {
    UrlEncodedForm form;
    form.add("name", "hello world");
    form.add("tag", "a+b");
    form.add("tag", "second"); // duplicates are preserved
    form.add("utf8", "\xC3\xA9t\xC3\xA9");

    const std::string encoded = form.encode();
    CHECK(encoded.find('+') != std::string::npos);
    const UrlEncodedForm back = UrlEncodedForm::decode(encoded);
    CHECK(back.size() == 4);
    CHECK(back.get("name").value() == "hello world");
    CHECK(back.getAll("tag").size() == 2);
    CHECK(back.getAll("tag")[1] == "second");
    CHECK(back.get("utf8").value() == "\xC3\xA9t\xC3\xA9");
    CHECK(!back.has("absent"));
    CHECK(back.has("tag"));

    CHECK(UrlEncodedForm::escape("a b&c=d") == "a+b%26c%3Dd");
    CHECK(UrlEncodedForm::unescape("a%20b%26c%3Dd") == "a b&c=d");
    CHECK(UrlEncodedForm::unescape("100%") == "100%"); // not a valid escape
    CHECK(UrlEncodedForm::decode("").empty());
    CHECK(UrlEncodedForm::decode("k=").get("k").value().empty());
}

TEST(url_encoded_form_message) {
    HttpResponse r;
    UrlEncodedForm form;
    form.add("q", "rust c++");
    form.add("page", "2");
    r.setUrlEncodedForm(form);
    CHECK(r.isMediaType("application", "x-www-form-urlencoded"));
    CHECK(r.body == "q=rust+c%2B%2B&page=2");

    const UrlEncodedForm back = Worker::defaultWorker()->sync_wait(r.toUrlEncodedForm());
    CHECK(back.get("q").value() == "rust c++");
    CHECK(back.get("page").value() == "2");
}

TEST(multipart_form_round_trip) {
    Form form;
    form.add("field", "value");
    form.add("multi", "one");
    form.add("multi", "two");
    form.addFile("upload", "hello.txt", "file contents", "text/plain");

    const std::string boundary = "----testBoundary123";
    const HttpResponse r = [&] {
        HttpResponse out;
        out.setForm(form, boundary);
        return out;
    }();

    CHECK(r.isMediaType("multipart", "form-data"));
    CHECK(r.mediaType().param("boundary") == boundary);

    const Form back = Worker::defaultWorker()->sync_wait(r.toForm());
    CHECK(back.size() == 4);
    CHECK(back.value("field").value() == "value");
    CHECK(back.findAll("multi").size() == 2);
    const Form::Part* file = back.find("upload");
    CHECK(file != nullptr);
    CHECK(file->filename == "hello.txt");
    CHECK(file->contentType == "text/plain");
    CHECK(file->data == "file contents");
    CHECK(back.names().size() == 4);
}

TEST(multipart_form_generated_boundary) {
    Form form;
    form.add("a", "1");
    HttpResponse r;
    r.setForm(form); // boundary generated and shared with the body
    const std::string boundary = r.mediaType().param("boundary");
    CHECK(!boundary.empty());
    auto& worker = *Worker::defaultWorker();
    CHECK(worker.sync_wait(r.toForm()).value("a").value() == "1");
}

TEST(form_rejects_bad_input) {
    CHECK_THROWS(FormError, Form::decode("no boundary here", "xyz"));
    CHECK_THROWS(FormError, Form::decode("--xyz\r\nnot-a-part", "xyz"));
    const std::string truncated =
        "--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--xyz--\r\n";
    CHECK_THROWS(FormError, Form::decode(truncated.substr(0, 40), "xyz"));

    auto& worker = *Worker::defaultWorker();
    HttpResponse wrong;
    wrong.headers.push_back({ "Content-Type", "text/plain" });
    wrong.body = "hello";
    CHECK_THROWS(FormError, worker.sync_wait(wrong.toForm()));

    HttpResponse none;
    none.body = "hello";
    CHECK_THROWS(FormError, worker.sync_wait(none.toForm())); // no Content-Type at all
}

TEST(query_parameters) {
    HttpRequest req("GET", "/search?q=hello%20world&page=2&page=3&flag");
    CHECK(req.path() == "/search");
    CHECK(req.query("q") == "hello world");
    CHECK(req.query("page") == "2");
    CHECK(req.queryAll("page").size() == 2);
    CHECK(req.queryAll("page")[1] == "3");
    CHECK(req.query("missing").empty());
    CHECK(req.query("flag") == "");
    CHECK(req.query("flag").empty()); // present but empty

    HttpRequest plain("GET", "/plain");
    CHECK(plain.path() == "/plain");
    CHECK(plain.queryAll("x").empty());

    // formField prefers the query, then the body.
    HttpRequest posted("POST", "/submit?a=fromQuery");
    UrlEncodedForm body;
    body.add("a", "fromBody");
    body.add("b", "onlyBody");
    posted.setUrlEncodedForm(body);
    auto& worker = *Worker::defaultWorker();
    CHECK(worker.sync_wait(posted.formField("a")).value() == "fromQuery");
    CHECK(worker.sync_wait(posted.formField("b")).value() == "onlyBody");
    CHECK(!worker.sync_wait(posted.formField("zz")).has_value());
}

// --------------------------------------------------------------- data pipe

TEST(body_pipe_collect) {
    auto seen = std::make_shared<std::vector<std::string>>();
    auto index = std::make_shared<size_t>(0);
    const std::vector<std::string> chunks = { "alpha", "-beta", "-gamma" };
    Body pipe = Body::fromPipe([chunks, index, seen](Canceller) -> Task<std::optional<Body::Chunk>> {
        seen->push_back("pull");
        if (*index >= chunks.size()) {
            co_return std::nullopt;
        }
        co_return chunks[(*index)++];
    });

    CHECK(pipe.isPipe());
    CHECK(!pipe.knownSize());
    CHECK(!pipe.empty()); // a pipe is never "empty" until it is drained
    CHECK(pipe.size() == 0);

    const std::string all = Worker::defaultWorker()->sync_wait(pipe.collect());
    CHECK(all == "alpha-beta-gamma");
    CHECK(seen->size() == 4); // three chunks plus the terminating pull

    Body buffered("bytes");
    CHECK(buffered.isBuffered());
    CHECK(buffered.knownSize());
    CHECK(buffered.size() == 5);
    CHECK(!buffered.empty());
    CHECK(Worker::defaultWorker()->sync_wait(buffered.collect()) == "bytes");
}

TEST(body_from_chunks_is_replayable) {
    Body body = Body::fromChunks({ "one", "two" });
    auto worker = Worker::defaultWorker();
    CHECK(worker->sync_wait(body.collect()) == "onetwo");
}

TEST(body_text_helper) {
    HttpResponse r;
    r.setText("plain");
    CHECK(r.isMediaType("text", "plain"));
    const std::string text = Worker::defaultWorker()->sync_wait(r.toText());
    CHECK(text == "plain");
}

TEST(body_pipe_response_streamed) {
    // A handler answers with a pipe: HTTP/1.1 must fall back to chunked
    // encoding and the client must reassemble the exact bytes.
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    w->push(runServer(&listener, [](HttpRequest) -> Task<HttpResponse> {
        auto step = std::make_shared<int>(0);
        HttpResponse r;
        r.body = Body::fromPipe([step](Canceller) -> Task<std::optional<Body::Chunk>> {
            if (*step >= 4) {
                co_return std::nullopt;
            }
            ++*step;
            co_return "chunk" + std::to_string(*step) + ";";
        });
        co_return r;
    }, stop.canceller));

    HttpResponse got = w->sync_wait(H1Client::get(urlFor(&listener, "/stream")));
    CHECK(got.status == 200);
    CHECK(got.body == "chunk1;chunk2;chunk3;chunk4;");
    stop.trigger();
    w->wait();
}

TEST(body_pipe_request_upload) {
    // The client uploads through a pipe; the server sees the whole body.
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    std::string seenBody;
    w->push(runServer(&listener, [&seenBody](HttpRequest req) -> Task<HttpResponse> {
        seenBody = co_await req.toText();
        HttpResponse r;
        r.body = "got:" + std::to_string(seenBody.size());
        co_return r;
    }, stop.canceller));

    auto& worker = *w;
    HttpResponse got = worker.sync_wait([&listener, port]() -> Task<HttpResponse> {
        Socket socket = co_await Socket::connect(kLoopback, port);
        H1Connection conn(std::make_unique<SocketStream>(std::move(socket)));
        HttpRequest req("POST", "/upload");
        req.headers.push_back({ "Host", kLoopback });
        req.headers.push_back({ "Connection", "close" });
        int step = 0;
        req.body = Body::fromPipe([&step](Canceller) -> Task<std::optional<Body::Chunk>> {
            if (step >= 100) {
                co_return std::nullopt;
            }
            ++step;
            co_return std::string(1000, 'x');
        });
        co_await conn.sendRequest(req);
        co_return co_await conn.recvResponse();
    }());
    CHECK(got.status == 200);
    CHECK(got.body == "got:100000");
    CHECK(seenBody.size() == 100000);
    stop.trigger();
    w->wait();
}

TEST(body_pipe_json_response) {
    // A pipe can carry JSON without materializing it first.
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    w->push(runServer(&listener, [](HttpRequest) -> Task<HttpResponse> {
        auto step = std::make_shared<int>(0);
        HttpResponse r;
        r.headers.push_back({ "Content-Type", "application/json" });
        r.body = Body::fromPipe([step](Canceller) -> Task<std::optional<Body::Chunk>> {
            if (*step >= 3) {
                co_return std::nullopt;
            }
            ++*step;
            co_return *step == 1 ? std::string(R"({"items":[)")
                                : (*step == 2 ? std::string("1,2,3") : std::string("]}"));
        });
        co_return r;
    }, stop.canceller));

    HttpResponse got = w->sync_wait(H1Client::get(
        "http://" + std::string(kLoopback) + ":" + std::to_string(port) + "/json"));
    CHECK(got.status == 200);
    const Json doc = w->sync_wait(got.toJson());
    CHECK(doc["items"].size() == 3);
    CHECK(doc["items"].at(2).asInt() == 3);
    stop.trigger();
    w->wait();
}

TEST(body_pipe_is_parsed_like_a_buffer) {
    // A pipe is drained by the codecs themselves: they are coroutines, so the
    // same call works for a buffered body and for one produced lazily.
    auto& worker = *Worker::defaultWorker();

    HttpResponse json;
    json.headers.push_back({ "Content-Type", "application/json" });
    json.body = Body::fromChunks({ R"JSON({"a":[)JSON", "1", ",2]}" });
    const Json doc = worker.sync_wait(json.toJson());
    CHECK(doc["a"].at(0).asInt() == 1);
    CHECK(doc["a"].at(1).asInt() == 2);

    HttpResponse form;
    form.body = Body::fromChunks({ "a=1&", "b=2" });
    const UrlEncodedForm fields = worker.sync_wait(form.toUrlEncodedForm());
    CHECK(fields.get("a").value() == "1");
    CHECK(fields.get("b").value() == "2");

    HttpResponse text;
    text.body = Body::fromChunks({ "he", "llo" });
    CHECK(worker.sync_wait(text.toText()) == "hello");
}

TEST(body_pipe_multipart_parsed) {
    auto& worker = *Worker::defaultWorker();
    Form form;
    form.add("a", "1");
    form.addFile("f", "n.txt", "bytes");

    HttpResponse r;
    r.headers.push_back({ "Content-Type", "multipart/form-data; boundary=B0UND" });
    r.body = Body::fromChunks({ form.encode("B0UND") });
    const Form back = worker.sync_wait(r.toForm());
    CHECK(back.size() == 2);
    CHECK(back.value("a").value() == "1");
    CHECK(back.find("f")->filename == "n.txt");

    // A request whose body is a pipe still answers formField().
    HttpRequest req("POST", "/x");
    req.body = Body::fromChunks({ "k=v" });
    CHECK(worker.sync_wait(req.formField("k")).value() == "v");
}

TEST(body_pipe_over_h2) {
    // The same pipe streams as DATA frames over HTTP/2.
    auto w = std::make_shared<ThreadPooledWorker>(4);
    Socket listener = Socket::bind(kLoopback, 0);
    const std::uint16_t port = listener.localPort();
    CancellerSource stop;
    w->push([](Socket* l, Canceller ct) -> Task<void> {
        co_await H2Server::serveH2c(std::move(*l), [](H2Request) -> Task<H2Response> {
            H2Response r;
            r.body = Body::fromChunks({ "abc", "def", "ghi" });
            co_return r;
        }, { }, ct);
    }(&listener, stop.canceller));

    const std::string url = "http://" + std::string(kLoopback) + ":" + std::to_string(port) + "/p";
    H2Response got = w->sync_wait(H2Client::get(url));
    CHECK(got.status == 200);
    CHECK(got.body == "abcdefghi");
    stop.trigger();
    w->wait();
}

TEST_MAIN()
