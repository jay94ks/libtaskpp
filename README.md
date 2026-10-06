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
                        AsyncMutex, whenAll / whenAny, Monitor, MonitorBackend
modules/core            core module sources -> taskpp::core
  src/                    implementation (+ src/backends: epoll, poll, select/WSAPoll on Windows)
  tests/                  dependency-free unit tests (ctest)
modules/socket          socket module sources -> taskpp::socket (`taskpp` namespace)
  src/Socket.cpp + SocketAddress.cpp + Dns.cpp   coroutine `Socket`, `SocketAddress`, `Dns`
  tests/                  loopback echo / timeout / refused / EOF tests (ctest)
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
co_await Worker::yield();
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
header): numeric factories, `resolve`, `host`/`port`/`toString`. `Dns`
resolves records as coroutines — numeric literals inline, hostnames through
c-ares (`third_party/c-ares` submodule, static build, driven by the Monitor
reactor with zero dedicated threads).

## License

MIT
