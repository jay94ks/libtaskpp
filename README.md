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
include/taskpp          common headers (Config, TimeSpan, Exceptions, umbrella taskpp.hpp)
modules/core            core module -> taskpp::core
  include/taskpp/core     Task, Worker, ThreadedWorker, ThreadPooledWorker, Canceller,
                          Timer (delay), AsyncQueue, Monitor, MonitorBackend
  src/                    implementation (+ src/backends: epoll, poll)
  tests/                  dependency-free unit tests (ctest)
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
Cancelable waits (`delay`, `AsyncQueue::wait`, `Monitor::wait/whenAny`) throw
`OperationCanceled`.

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

The reactor runs on its own thread over a pluggable `MonitorBackend`
(epoll on Linux, poll on other POSIX systems). `FD_ERROR` / `FD_HANGUP` are
always reported. See [docs/DESIGN.md](docs/DESIGN.md) for adding kqueue / IOCP.

## License

MIT
