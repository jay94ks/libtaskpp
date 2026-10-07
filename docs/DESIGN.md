# libtaskpp design notes

This document lists the gaps found in the initial specification (the illustrative
snippets for `Task`, `Canceller`, `Worker` and `Monitor`) and how each one is
resolved in the implementation.

## 1. Repository layout

| Spec | Gap | Resolution |
|---|---|---|
| `include/taskpp` = common headers, `modules/core` = core | Where module headers live, and how modules are built and consumed, is not specified. | `include/taskpp` holds every public header (`Config.hpp`, `TimeSpan.hpp`, `Exceptions.hpp`, the umbrella `taskpp.hpp`, plus `core/` with all core headers) behind the `taskpp::common` / `taskpp::core` INTERFACE include paths. Each module `modules/<m>` now holds only `src/`, `tests/` and produces `taskpp::<m>`. A new module is one directory plus one entry in `TASKPP_MODULES`. |
| TLS has nothing to do with HTTP, yet lived in the `http` module | `taskpp::http::TlsStream` forced anything that only wanted encryption to pull in the whole HTTP stack. | TLS is its own module `modules/tls` producing `taskpp::tls`, depending only on `core` + `socket`. The shared `Stream` abstraction sits in `core`; `SocketStream` sits in `socket`. `http` depends on `tls` and re-uses it through `<taskpp/tls/Tls.hpp>`. |

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
| Semantics of `whenAny` | Completes as soon as at least one descriptor is ready, and returns **every** descriptor found ready in that poll cycle (duplicate fds are merged). Overloads accept `std::span<const IoFd>`, an initializer list, or `std::vector<IoEventInfo>` for a different interest per fd. |
| Several coroutines waiting on the same fd | The monitor keeps a registration list per fd and arms the backend with the union of their interests. Each waiter only receives the events it asked for. |
| Closing an fd while waiting on it | `Monitor::cancel(fd)` aborts every wait on it (`OperationCanceled`). Call it before `close()`. |
| One-shot vs persistent | Waits are one-shot. The backend is level-triggered, and each fd is re-armed with whatever interest remains, so there is no busy loop and no lost wakeup. |
| Extensibility (epoll, IOCP, ...) | `MonitorBackend` provides `update(fd, old, new)`, `poll(out, timeout)` and `wakeup()`. Shipped backends are `epoll` (Linux, eventfd wakeup), `poll` (POSIX, self-pipe) and `select` (Windows, sockets only, loopback-TCP wakeup). Descriptors are `IoFd` (`std::intptr_t`: a POSIX fd or a Windows `SOCKET`; `int` converts implicitly). You can construct a `Monitor` with any backend, and the static `Monitor::wait/whenAny` helpers use the process-wide `defaultMonitor()`. |

### Adding kqueue / IOCP

* **kqueue** fits `MonitorBackend` directly: `update` maps to `EV_ADD`/`EV_DELETE`
  on `EVFILT_READ`/`EVFILT_WRITE`, and `wakeup` maps to `EVFILT_USER`.
* **IOCP** is completion based, not readiness based. There are two options:
  1. Keep the readiness model on Windows through a socket-only backend
     (shipped: `select()` over Winsock; `WSAPoll` or AFD polling as done by
     wepoll/mio are alternatives) behind `MonitorBackend`.
     The `Monitor` API is unchanged apart from the widened `IoFd` descriptor type.
  2. Add a completion-based `IoService` module next to `Monitor`
     (`co_await socket.read(buffer)`) that issues overlapped operations. One
     IOCP thread dequeues completions and posts the resumption through the same
     `detail::Completion` / `ResumeTarget` machinery, so worker affinity and
     cancellation (`CancelIoEx` from `onTriggered`) behave the same as they do
     for `Monitor`.

## 6. Missing primitives that the samples rely on

* `TimeSpan` (`TimeSpan::fromSeconds(5)`) is in global `include/taskpp`.
* `queue.wait()` is provided by `AsyncQueue<T>` (MPMC, FIFO waiters, cancelable, `close()`).
* Bounded back-pressure channels: `Channel<T>(capacity)` (`send`/`receive`, `trySend`/`tryReceive`, `close()`).
* `AsyncMutex` (`lock(ct)` -> RAII `ScopedLock`, FIFO, cancelable, `tryLock()`).
* Task combinators: `whenAll` (vector + variadic tuple), `whenAny` (vector + variadic variant), `withTimeout`.
* `delay(TimeSpan, Canceller)`.
* `OperationCanceled`, `QueueClosed`, `ChannelClosed` (derives from `QueueClosed`) and `Timeout` (derives from `OperationCanceled`) exceptions.

## 7. Known limitations / future work (all implemented)

* `whenAll` / `whenAny` combinators over tasks, an async mutex, and channels with
  back-pressure are implemented in `taskpp::core` (`WhenAll.hpp`, `AsyncMutex.hpp`,
  `Channel.hpp`, all in the `taskpp` namespace and re-exported by `Core.hpp` /
  `taskpp.hpp`):
  * `whenAll(vector<Task<T>>) -> Task<vector<T>>`, `whenAll(vector<Task<void>>)`,
    variadic `whenAll(Task<Ts>...) -> Task<tuple<...>>` (`void` maps to
    `std::monostate`), plus `whenAllWithCanceller`.
  * `whenAny(vector<Task<T>>) -> Task<WhenAnyResult<T>>` (`{index, value}`),
    `whenAny(vector<Task<void>>) -> Task<size_t>`, variadic
    `whenAny(Task<Ts>...) -> Task<variant<...>>` (`variant::index()` is the winner),
    plus `whenAnyWithCanceller`. Losers keep running in the background until they
    finish so no suspended frame is destroyed mid-wait.
  * `AsyncMutex` (`co_await m.lock(ct)` -> RAII `ScopedLock`, FIFO, cancelable,
    `tryLock()`, worker affinity via `detail::Completion`).
  * `Channel<T>(capacity)` with back-pressure (`co_await send/recv`, `trySend` /
    `tryReceive`, `close()`, `ChannelClosed` which derives from `QueueClosed`).
* The monitor builds on Windows over a socket-only `select()` backend
  (`WsaPollBackend.cpp`, `MonitorBackend::createWsaPoll()`, backend name
  `"select"`; §5 option 1). `IoFd` (`std::intptr_t`) holds a POSIX fd or a Windows
  `SOCKET`; existing `int` code converts implicitly. Regular files/pipes remain
  POSIX-only; on Windows only sockets are pollable.
* A wait that is never completed (no event and no canceller) is still owned by its
  `Task`, like an unfinished `std::future`, but three mitigations exist:
  * `withTimeout(task, span, ct) -> Task<T>` races any task against a deadline and
    throws `Timeout` (derives from `OperationCanceled`, so existing handlers work).
    The loser runs in the background until it finishes.
  * Destroying a task suspended on `delay` / `AsyncQueue` / `Channel` / `AsyncMutex` /
    `Monitor` / combinators is safe: awaitables unlink/cancel in their
    destructors and never resume a destroyed frame (a resumption already queued on
    a worker before destruction remains a user-side race, as with any executor).
  * Guidance: always pass a `Canceller` (`cancelAfter` / `withTimeout`) to waits
    that might never complete.

## 8. TLS module

TLS was split out of `http` into its own `tls` module (`taskpp::tls`) so that it
depends only on `core` + `socket`, not on HTTP. The `Stream` abstraction lives
in `core` (`Stream`, transport independent); `SocketStream` lives in `socket`
because it binds the abstraction to sockets. `http` depends on `tls`.

Design points that are easy to get wrong and are called out here because they
were verified against OpenSSL, not just against our own tests:

* **PSK binder (RFC 8446 4.2.11.2).** The binder is
  `HMAC(finished_key, Hash(truncated ClientHello))` where
  `finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)`. Using the
  binder key directly "works" between our own client and server and fails with
  every other implementation. The truncated message ends after the
  `identities` field, but **all length fields keep their full values** -- only
  the binder bytes are omitted.
* **Record version.** `legacy_record_version` must be 0x0303 everywhere except
  the initial ClientHello, where 0x0301 is allowed (RFC 8446 5.1). OpenSSL
  sends 0x0301 there, so the check is relaxed only while no keys exist.
* **Unknown extensions must be ignored**, not rejected: a strict `e.end()` on
  every extension makes us reject OpenSSL's ClientHello outright.
* **Resumption PSK derivation.** The ticket binds the *resumption master
  secret* and the ticket nonce; the PSK is
  `HKDF-Expand-Label(res_master, "resumption", ticket_nonce, 32)` on both
  sides. Storing a fresh random PSK in the ticket makes the client's derived
  PSK differ from the server's.
* **`txEncrypted` starts right after the ServerHello** (RFC 8446 4.1.3), not at
  Finished -- otherwise a mutual-TLS client sends its Certificate and
  CertificateVerify in the clear.
* **HelloRetryRequest** resets the transcript to the synthetic `message_hash`
  message. A retry drops any offered PSK (its binder no longer applies).
* The session `Finished` key (`res master`) is computed over the transcript
  through the *client* Finished; both sides derive the resumption PSK from that
  single value, so no per-session server state is needed.

## 9. HTTP/2 client concurrency

The client is multiplexed by a single reader pump that owns every inbound
frame, so `H2Connection::request` can be called concurrently. Three invariants
make it work, and each was a real bug found by testing:

* **Encode order, id order and wire order must be the same sequence.** HPACK is
  sequential and RFC 9113 5.1.1 requires request streams to open with strictly
  increasing ids. Assigning the stream id in a separate critical section from
  the HPACK encoding lets two callers encode in one order and write in another,
  which corrupts the peer's dynamic table and silently drops streams. All three
  now happen under `codecLock` then `writeLock`, always in that order.
* **Never hold the wire lock while parked on flow control.** The pump needs the
  same lock to send WINDOW_UPDATEs, PING and SETTINGS acknowledgements, so
  `sendData` releases it before waiting for credit.
* **CONTINUATION frames are assembled in the pump**, not in the per-stream
  consumer: otherwise a header block split across frames would let the pump read
  a frame belonging to another stream in the middle of the block.
* Server push is declined via `SETTINGS_ENABLE_PUSH = 0` plus
  `RST_STREAM(CANCEL)` on any `PUSH_PROMISE` that arrives anyway (RFC 9113
  8.4); the promise is still reported through `pushPromises()`.
* GOAWAY is honoured: streams above `last_stream_id` are reported as
  `REFUSED_STREAM` (retryable on a fresh connection) and no new request is sent
  afterwards.

## 10. Message bodies: pipes, forms, JSON

`HttpRequest` and `HttpResponse` used to carry a bare `std::string body`, which
forced a large payload to be materialised and made every content type the
caller's problem. They now share a `HttpMessage` base holding `Headers` and a
`Body`, and H2's request/response types derive from it too, so one set of
codecs works over both protocols.

* **`Body` is either bytes or a pipe.** `Body::fromPipe(fn)` takes
  `Task<std::optional<Chunk>>(Canceller)`: return the next chunk, `nullopt`
  when finished. A pipe has no known length, so HTTP/1.1 sends
  `Transfer-Encoding: chunked` and HTTP/2 one DATA frame per chunk. Both
  directions need one chunk of lookahead so `END_STREAM` lands on the final
  frame; the HTTP/2 path originally never sent it and hung the peer, which is
  why the pipe tests assert the exact reassembled bytes.
* **The narrowing constructors of `Body` are explicit.** With an implicit
  `std::string` -> `Body` conversion, `body == "text"` is ambiguous between
  `operator==(const Body&)` and `operator==(std::string_view)`. Assignment
  operators keep `message.body = "text"` ergonomic without the ambiguity.
* **The readers are coroutines.** `toJson()`, `toForm()`, `toUrlEncodedForm()`
  and `toText()` all return `Task<...>` and drain a pipe body themselves.
  Making them synchronous and throwing "body is a pipe" was wrong: it forced
  every caller to branch on whether the body happened to be buffered, for no
  gain, since `Body::collect()` already suspends. A buffered body returns
  without suspending, so the async form is free. `HttpRequest::formField()`
  follows the same rule.
* **`trim` must eat `\r`.** Multipart headers are split on `\n`, so every line
  keeps its CR; without this, `filename` came back as `"a.txt"` *with the
  quotes and a trailing CR* instead of `a.txt`.
* **Urlencoding follows the WHATWG byte set** (`*-._` and alphanumerics stay
  literal, space becomes `+`, everything else is `%XX`), which is what HTML
  forms and every server-side decoder expect.
* **`std::from_chars` for integers.** `strtoll` reports `ERANGE` for exactly
  `INT64_MAX` on MSVC, so `9223372036854775807` silently degraded to a double.

## 11. Testing notes

* All tests are loopback and dependency free; `ctest` runs the same 13 suites
  under GCC (WSL) and MSVC, plus an ASan+UBSan build.
* The body codecs are also checked against real implementations in both
  directions: Python's `email` MIME parser and `json` module parse what we
  emit, and we parse what `curl -F` / `curl --data-urlencode` emit.
* A coroutine lambda must not capture by reference when it is passed straight
  to `push`: the closure dies before the coroutine runs. Use the
  parameter-style form (`[](Args...) -> Task<T> {}(args...)`) that the other
  tests use.
* `HttpResponse::status` defaults to 200, so 0 is the only safe "unset"
  sentinel for out-parameters.
* Closing a socket can discard bytes the peer has not read yet (Windows sends an
  RST). Tests that depend on a peer reading everything park until the test
  signals completion instead of hanging up.
