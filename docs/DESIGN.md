# libtaskpp design notes

This document lists the gaps found in the initial specification (the illustrative
snippets for `Task`, `Canceller`, `Worker` and `Monitor`) and how each one is
resolved in the implementation.

## 1. Repository layout

| Spec | Gap | Resolution |
|---|---|---|
| `include/taskpp` = common headers, `modules/core` = core | Where module headers live, and how modules are built and consumed, is not specified. | `include/taskpp` holds only module-independent headers (`Config.hpp`, `TimeSpan.hpp`, `Exceptions.hpp`, the umbrella `taskpp.hpp`) behind the `taskpp::common` INTERFACE target. Each module `modules/<m>` has its own `include/taskpp/<m>/`, `src/`, `tests/` and produces `taskpp::<m>`. A new module is one directory plus one entry in `TASKPP_MODULES`. |

## 2. Task

| Gap | Resolution |
|---|---|
| Eager or lazy? Who owns the frame? | **Lazy**, move-only, owns its frame. `co_await` runs it inline with symmetric transfer, so long `co_await` chains do not grow the stack. GCC only emits the tail call when optimizing, so unoptimized GCC builds use one stack frame per awaiting level. |
| `Task` vs `Task<void>` | `template<typename T = void> class Task`, so `Task<>` and `Task<void>` are the same type. |
| Exceptions | Stored in the promise and rethrown from `co_await` / `sync_wait`. |
| Fire-and-forget needs an owner | `Worker::push` wraps the task in a self-destroying root coroutine that is tracked by the worker (`wait()`, `pendingCount()`). |
| An exception escaping a pushed task has nowhere to go | `Worker::setUnhandledExceptionHandler`. The default handler prints to stderr. |
| References | `Task<T&>` is rejected by a `static_assert`. Use a pointer or `std::reference_wrapper`. |

## 3. Canceller

| Gap | Resolution |
|---|---|
| `cs.canceller` (no parentheses) in the sample | `CancellerSource::canceller` is a public `const Canceller` member, so the sample compiles as written. Copies of a source share one signal. |
| Waiting on `queue.wait()` cannot observe `ct.isTriggered()` until an item arrives | Every blocking awaitable takes an optional `Canceller` (`queue.wait(ct)`, `delay(t, ct)`, `Monitor::wait(fd, e, ct)`) and throws `OperationCanceled` when it is triggered. |
| `cancelAfter` needs a clock | `TimerService` is a single timer thread. Calling `cancelAfter` again re-arms the deadline. The timer is dropped with the last copy of the source. |
| Composition | `CancellerSource(parent)` creates a linked source: the parent triggers the child, never the reverse. `Canceller::onTriggered(fn)` returns an RAII `CancelRegistration`. |
| Thread safety of callbacks | Built on `std::stop_source` / `std::stop_callback`. Unregistering waits for a callback that is running on another thread. |
| Timeouts for I/O | No separate timeout parameter. Use `CancellerSource::cancelAfter` and pass its `canceller`. |

## 4. Worker

| Gap | Resolution |
|---|---|
| Minimal contract for implementations | `virtual void schedule(std::coroutine_handle<>)` is the only pure virtual. `push`, `wait`, `sync_wait`, `yield` and `switchTo` are built on it. Custom workers wrap each `resume()` in `Worker::ExecutionScope` so that `currentWorker()` works. |
| `currentWorker()` on a thread that is not a worker | Returns `nullptr`. Workers must be owned by `std::shared_ptr` (as in the spec's `make_shared`). |
| `sync_wait` / `wait` called from the worker's own thread deadlocks | Both detect it and throw `std::logic_error`. Use `co_await` instead. |
| Which thread continues after I/O, a timer, a queue push or a cancellation? | **Affinity.** When a coroutine suspends, the awaitable captures the current worker (`detail::ResumeTarget`) and posts the resumption back to it. Reactor, timer and producer threads never run user code. If that worker is gone, the coroutine resumes on the default worker. Resuming inline is the last resort, used only during process shutdown. |
| A race between completion and suspension | `detail::Completion` is a one-shot latch that admits exactly one winner (event, timer or cancel). Resumption is gated until `await_suspend` has finished arming, so a racing completer can never resume (and so destroy) an awaiter that is still being set up. |
| Worker lifetime | The destructor drains the run queue and joins its threads. The run-queue state is shared with the threads, so destroying a worker from one of its own tasks is safe: that thread is detached and finishes the drain. |
| Default worker | `Worker::defaultWorker()` is a lazily created `ThreadPooledWorker(hardware_concurrency)`. It can be replaced with `setDefaultWorker` and is drained at static destruction. |
| Moving between workers | `co_await Worker::switchTo(w)`, `co_await Worker::yield()`. |

`ThreadedWorker` runs one dedicated thread, so its tasks never run in parallel with
each other. `ThreadPooledWorker(n)` runs N threads that share one FIFO queue.
Work stealing and per-thread queues are possible future optimizations behind the
same interface.

## 5. Monitor (I/O readiness)

| Gap | Resolution |
|---|---|
| `FD_READ` / `FD_WRITE` collide with `<winsock2.h>` macros | Canonical names are `IoRead`, `IoWrite`, `IoError` and `IoHangup`. The `FD_*` constants are defined only if they are not already macros. The values match winsock's (1, 2). |
| Return value of `wait` | The ready flags (`int`). Errors and hangups are always reported, even when not requested. |
| Semantics of `whenAny` | Completes as soon as at least one descriptor is ready, and returns **every** descriptor found ready in that poll cycle (duplicate fds are merged). Overloads accept `std::span<const int>`, an initializer list, or `std::vector<IoEventInfo>` for a different interest per fd. |
| Several coroutines waiting on the same fd | The monitor keeps a registration list per fd and arms the backend with the union of their interests. Each waiter only receives the events it asked for. |
| Closing an fd while waiting on it | `Monitor::cancel(fd)` aborts every wait on it (`OperationCanceled`). Call it before `close()`. |
| One-shot vs persistent | Waits are one-shot. The backend is level-triggered, and each fd is re-armed with whatever interest remains, so there is no busy loop and no lost wakeup. |
| Extensibility (epoll, IOCP, ...) | `MonitorBackend` provides `update(fd, old, new)`, `poll(out, timeout)` and `wakeup()`. Shipped backends are `epoll` (Linux, eventfd wakeup) and `poll` (POSIX, self-pipe). You can construct a `Monitor` with any backend, and the static `Monitor::wait/whenAny` helpers use the process-wide `defaultMonitor()`. |

### Adding kqueue / IOCP

* **kqueue** fits `MonitorBackend` directly: `update` maps to `EV_ADD`/`EV_DELETE`
  on `EVFILT_READ`/`EVFILT_WRITE`, and `wakeup` maps to `EVFILT_USER`.
* **IOCP** is completion based, not readiness based. There are two options:
  1. Keep the readiness model on Windows through a socket-only backend
     (`WSAPoll`, or AFD polling as done by wepoll/mio) behind `MonitorBackend`.
     The `Monitor` API does not change.
  2. Add a completion-based `IoService` module next to `Monitor`
     (`co_await socket.read(buffer)`) that issues overlapped operations. One
     IOCP thread dequeues completions and posts the resumption through the same
     `detail::Completion` / `ResumeTarget` machinery, so worker affinity and
     cancellation (`CancelIoEx` from `onTriggered`) behave the same as they do
     for `Monitor`.

## 6. Missing primitives that the samples rely on

* `TimeSpan` (`TimeSpan::fromSeconds(5)`) is in common `include/taskpp`.
* `queue.wait()` is provided by `AsyncQueue<T>` (MPMC, FIFO waiters, cancelable, `close()`).
* `delay(TimeSpan, Canceller)`.
* `OperationCanceled` and `QueueClosed` exceptions.

## 7. Known limitations / future work

* `whenAll` / `whenAny` combinators over tasks, an async mutex, and channels with
  back-pressure are not implemented.
* The monitor is POSIX-only for now (see §5 for the Windows plan).
* A wait that is never completed (no event and no canceller) keeps its coroutine
  frame alive forever, the same as an unfinished `std::future`.
