# libtaskpp

An asynchronous coroutine library for C++20 (or above).

```cpp
#include <taskpp/taskpp.hpp>
using namespace taskpp;

Task<int> coroutineFunction(Canceller ct) {
    ct.throwIfCanceled();
    co_await delay(TimeSpan::fromMilliseconds(10), ct);
    co_return 123;
}

int main() {
    std::shared_ptr<Worker> w = std::make_shared<ThreadedWorker>();
    int v = w->sync_wait(coroutineFunction(Canceller::none()));   // 123
}
```

## Layout

```
include/taskpp          global headers (all public API, `taskpp` namespace)
  Config.hpp, TimeSpan.hpp, Exceptions.hpp, umbrella taskpp.hpp
  core/                 core headers: Task, Worker, ThreadedWorker, ThreadPooledWorker,
                        Canceller, Timer (delay, withTimeout), AsyncQueue, Channel,
                        AsyncMutex, whenAll / whenAny, Monitor, MonitorBackend, Stream
modules/core            core module sources -> taskpp::core
  src/                    implementation (+ src/backends: epoll, poll, select/WSAPoll on Windows)
  tests/                  dependency-free unit tests (ctest)
modules/socket          socket module sources -> taskpp::socket (`taskpp` namespace)
  src/Socket.cpp + SocketAddress.cpp + Dns.cpp + SocketStream.cpp
                          coroutine `Socket`, `SocketAddress`, `Dns`, `SocketStream`
  tests/                  loopback echo / timeout / refused / EOF tests (ctest)
modules/tls             tls module sources -> taskpp::tls
  src/Tls.cpp              TLS 1.3 client + server (RFC 8446), crypto from libcertpp only
  tests/                  loopback TLS tests (ctest)
modules/http              http module sources -> taskpp::http, optional (TASKPP_BUILD_HTTP)
  src/                    H1 client/server, HTTP/2 client/server + HPACK
                          (RFC 7541 table generated)
  tests/                  loopback H1/H2 tests (ctest)
third_party/c-ares        DNS backend submodule (static build, unmodified)
third_party/libcertpp     cert/hash/crypto submodule (static build, unmodified)
examples/               runnable samples
docs/DESIGN.md          gap analysis and design decisions
```

Each directory under `modules/` is a separate library target `taskpp::<name>`;
`taskpp::taskpp` links them all.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Options: `TASKPP_BUILD_TESTS`, `TASKPP_BUILD_EXAMPLES` (both on when top-level).
To consume: `add_subdirectory(libtaskpp)` and `target_link_libraries(app PRIVATE taskpp::taskpp)`.

## Overview

### Tasks

`Task<T>` (and `Task<void>`) is a lazy, move-only coroutine. It starts when it is
`co_await`ed (it runs inline, using symmetric transfer) or handed to a worker.
Exceptions propagate through `co_await`.

### Cancellation

```cpp
Task<void> coroutineNoReturn(Canceller ct) {
    while (ct.isTriggered() == false) {
        auto item = co_await queue.wait(ct);   // pass ct so the wait itself is interruptible
        // ...
    }
}

Task<void> sampleForCanceller() {
    CancellerSource cs;
    cs.cancelAfter(TimeSpan::fromSeconds(5));
    co_await coroutineNoReturn(cs.canceller);
    if (!cs.isTriggered()) {
        cs.trigger();
    }
}
```

`Canceller` is the observer (`isTriggered`, `throwIfCanceled`, `onTriggered`),
`CancellerSource` the owner (`trigger`, `cancelAfter`, linked to parent cancellers).
Cancelable waits (`delay`, `AsyncQueue::wait`, `Channel::send`/`receive`,
`AsyncMutex::lock`, `Monitor::wait`/`whenAny`, `whenAll`/`whenAny`, `withTimeout`)
throw `OperationCanceled`.

### Combining tasks

```cpp
std::vector<int> v = co_await whenAll(tasks);          // vector<Task<T>> -> vector<T>, in order
auto [a, b] = co_await whenAll(t1, t2);                // variadic -> tuple (void maps to monostate)
auto first = co_await whenAny(tasks);                  // { index, value } of the first finisher
int x = co_await withTimeout(task(), TimeSpan::fromSeconds(2));  // throws Timeout on expiry
```

Losers keep running in the background until they finish, so no suspended frame
is destroyed mid-wait.

### Mutexes and channels

```cpp
AsyncMutex m;
{
    auto guard = co_await m.lock(ct);   // FIFO, cancelable, worker affinity
}

Channel<int> ch(16);                    // bounded, back-pressure
co_await ch.send(1, ct);                // suspends when full
int item = co_await ch.receive(ct);     // suspends when empty
ch.close();                             // receivers drain, then throw ChannelClosed
```

### Workers

```cpp
std::shared_ptr<Worker> w = std::make_shared<ThreadedWorker>();   // or ThreadPooledWorker(n)

w->push(task());                // start, don't wait
w->wait();                      // wait for every pushed task
int v = w->sync_wait(task2());  // run and block for the result

Worker::currentWorker();        // the worker running this thread (nullptr elsewhere)
Worker::defaultWorker();        // process wide ThreadPooledWorker
co_await Worker::yield();       // or the free spelling: co_await yield();
co_await Worker::switchTo(otherWorker);
```

A coroutine that suspends on a timer, queue, cancellation or I/O is resumed **on
the worker it was running on**. Custom workers only implement `schedule(handle)`.

### I/O monitoring

```cpp
int e = co_await Monitor::wait(fd, FD_READ | FD_WRITE);              // ready flags

std::vector<IoEventInfo> eves = co_await Monitor::whenAny({ a, b }, FD_READ);
```

`IoFd` (`std::intptr_t`) holds a POSIX fd or a Windows `SOCKET`; plain `int`
code converts implicitly. The reactor runs on its own thread over a pluggable
`MonitorBackend` (epoll on Linux, poll on other POSIX systems, select over
sockets on Windows — regular files/pipes stay POSIX-only).
`FD_ERROR` / `FD_HANGUP` are always reported. See [docs/DESIGN.md](docs/DESIGN.md)
for the Windows socket-only note and for adding kqueue / IOCP.

### Sockets

```cpp
Socket listener = Socket::bind("127.0.0.1", 0);              // ephemeral port
Socket conn = co_await listener.accept(ct);                // server side

Socket s = co_await Socket::connect("127.0.0.1", port, ct);
co_await s.sendAll(std::span(data), ct);                   // suspends when unsendable
std::size_t n = co_await s.recvSome(std::span(buffer), ct); // 0 = orderly shutdown
co_await s.recvExact(std::span(buffer), ct);               // throws SocketClosed on early EOF
```

`Socket` is a move-only RAII wrapper over a non-blocking handle — one class
for TCP and UDP (`SocketType` is a creation option, never stored state). Every
member suspends on the calling worker (affinity via the `Monitor` reactor) and
takes an optional `Canceller`; deadlines via `withTimeout`. Buffers must
outlive the operation. `close()` aborts parked waits first
(`OperationCanceled`), then releases the handle.

`SocketAddress` is a header-clean value type (no OS headers in the public
header): numeric factories, `host`/`port`/`toString`. `Dns` resolves records
as coroutines -- numeric literals inline, hostnames through c-ares
(`third_party/c-ares` submodule, static build, driven by the Monitor reactor
with zero dedicated threads).

### TLS 1.3

The `tls` module (`taskpp::tls`) is independent of HTTP; it only needs a
connected socket. Everything lives in `taskpp::tls`.

```cpp
TlsConfig server;
server.certificateChain = { leafWithKey };                 // leaf first
TlsStream accepted = co_await TlsStream::accept(std::move(raw), server);

TlsConfig client;
client.trustAnchors = { ca };                              // path validation
client.serverName = "example.com";                         // SNI + hostname check
TlsStream tls = co_await TlsStream::connect(std::move(raw), client);
```

TLS 1.3 only (X25519, AES-128-GCM, ChaCha20-Poly1305, ECDSA P-256 / Ed25519),
handshake + records implemented here; every hash, AEAD, signature and
certificate primitive comes from libcertpp (`third_party/libcertpp`
submodule, static build, unmodified) and nothing else. Path validation
(dates, basicConstraints, keyUsage, EKU, SAN/CN, anchor trust) is ours --
libcertpp checks single links only. Afterwards a `TlsStream` is a plain
`Stream`, so `H1Connection`/`H2Connection` run over it unchanged.

Beyond the plain handshake:

```cpp
// Session resumption (PSK tickets, no early data).
server.ticketKey = my32Bytes;                  // server: enables ticket issuance
client.pskCache = mySharedCache;               // client: share one across connections
if (tls.resumed()) { /* second handshake, no certificates */ }

// Mutual TLS.
server.verifyClient = true;
server.clientTrustAnchors = { ca };
client.clientCertificateChain = { clientLeaf };

// HelloRetryRequest: handled automatically in both directions.
```

Interoperability is verified against OpenSSL in both directions: our server
against `openssl s_client` (handshake, ALPN, and OpenSSL deriving a resumption
PSK from our `NewSessionTicket`), and our client against `openssl s_server`,
including a genuine second connection resumed from OpenSSL's own ticket.

### HTTP/1.1 and HTTP/2

```cpp
HttpResponse r = co_await H1Client::get("http://example.com/");
H2Response r2 = co_await H2Client::get("http://example.com/");   // h2c
H2Response r3 = co_await H2Client::request("GET", url, {}, {}, tls); // h2 over TLS
```

`H1Server`/`H2Server` run accept loops on a worker (`serveH2c` for cleartext
prior-knowledge, `serveTls` for ALPN `h2`). HPACK static/dynamic tables and
Huffman decoding follow RFC 7541 (table generated from the RFC text, checked
against python-hpack vectors); flow control is enforced both directions.

`Expect: 100-continue` is honoured: the server defers reading the body until
your `H1ExpectDecision` accepts it (or answers `417` without reading it), and
the client steps over interim 1xx responses -- `100 Continue`, `103 Early
Hints` -- which are available through `interimResponses()`.

The HTTP/2 client multiplexes: a single reader pump dispatches frames to
per-stream state, so `H2Connection::request` may be called concurrently and up
to `min(peer's MAX_CONCURRENT_STREAMS, limits.maxStreams)` requests are in
flight. Server push is declined (`SETTINGS_ENABLE_PUSH = 0`, plus
`RST_STREAM(CANCEL)` on any `PUSH_PROMISE` that arrives anyway), and GOAWAY is
honoured: streams the server says it never processed surface as
`H2Error` with `REFUSED_STREAM`, which is safe to retry on a new connection
(`H2Error::retryable()`).

### Bodies: pipes, forms and JSON

A message body is a `Body`. It is either a buffer or a **data pipe** that
produces its bytes one chunk at a time, so a handler can stream a large payload
or an incremental generator without ever holding it in memory:

```cpp
HttpResponse handler(HttpRequest) {
    HttpResponse r;
    r.body = Body::fromPipe([](Canceller ct) -> Task<std::optional<Body::Chunk>> {
        while (auto line = co_await readLine(ct)) {
            co_return *line;              // next chunk...
        }
        co_return std::nullopt;           // ...or nullopt to finish
    });
    co_return r;
}
```

A pipe has no known length, so HTTP/1.1 switches to `Transfer-Encoding:
chunked` automatically and HTTP/2 sends one DATA frame per chunk.

The `to*()` readers are **coroutines**, not plain functions: they drain a pipe
body themselves, so the same call works for a buffered body and one produced
lazily (a buffered body returns without ever suspending).

```cpp
Json doc = co_await r.toJson();              // collects a pipe if there is one
Form form = co_await req.toForm();            // dispatches on Content-Type
auto q = co_await req.formField("q");        // query first, then the body
```

`HttpRequest` and `HttpResponse` share a `HttpMessage` base that knows the
content type and exposes the codecs:

```cpp
// JSON
r.setJson(doc);                       // serializes + sets application/json
Json doc = co_await r.toJson();       // parses (throws JsonError)

// urlencoded forms
UrlEncodedForm f;
f.add("q", "rust c++");               // duplicates preserved
r.setUrlEncodedForm(f);               // application/x-www-form-urlencoded
co_await r.toUrlEncodedForm();        // -> UrlEncodedForm

// multipart forms (RFC 7578)
Form form;
form.add("title", "hello");
form.addFile("upload", "a.txt", bytes, "text/plain");
r.setForm(form);                      // generates a boundary and sets the header
Form back = co_await r.toForm();      // dispatches on Content-Type
back.find("upload")->filename;
```

`Json` is a small RFC 8259 value type (null/bool/number/string/array/object)
with a strict parser -- trailing commas, unquoted keys, lone surrogates and
control characters in strings are all errors. Object keys are sorted, so
serializing the same value twice always produces the same bytes; integers keep
an exact `int64_t` alongside the `double` so they round-trip losslessly.
`MediaType` parses `Content-Type` including parameters, and `HttpRequest`
adds `query()`, `queryAll()`, `path()` and `formField()` (query first, then
body).

Both directions are verified against real implementations: Python's `email`
MIME parser and `json` module accept what this library produces, and this
library parses what `curl -F` and `curl --data-urlencode` produce.

## License

MIT
