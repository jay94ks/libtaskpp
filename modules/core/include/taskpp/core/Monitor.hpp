#pragma once
#include <taskpp/Config.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/MonitorBackend.hpp>
#include <taskpp/core/detail/Completion.hpp>

#include <coroutine>
#include <initializer_list>
#include <memory>
#include <span>
#include <vector>

namespace taskpp {

class Monitor;

namespace detail {

struct IoWaiter {
    std::vector<IoEventInfo> interests;
    std::vector<IoEventInfo> results;
    Completion completion;
    bool registered = false;    // guarded by the monitor mutex.
    bool aborted = false;       // written by the completion winner only.
};

class IoAwaitableBase {
public:
    IoAwaitableBase(const IoAwaitableBase&) = delete;
    IoAwaitableBase& operator=(const IoAwaitableBase&) = delete;

    bool await_ready() const noexcept { return false; }
    bool await_suspend(std::coroutine_handle<> handle);

protected:
    IoAwaitableBase(Monitor& monitor, std::vector<IoEventInfo> interests, Canceller canceller);
    ~IoAwaitableBase() = default;

    /** Disarms and throws `OperationCanceled` if aborted; returns the ready set. */
    std::vector<IoEventInfo>& finish();

private:
    Monitor* monitor_;
    Canceller canceller_;
    IoWaiter waiter_;
    CancelRegistration registration_;
};

} // namespace detail

/** `co_await Monitor::wait(fd, events)` -> the ready `IoEvent` flags of `fd`. */
class IoWaitAwaitable : public detail::IoAwaitableBase {
public:
    int await_resume();

private:
    friend class Monitor;
    IoWaitAwaitable(Monitor& monitor, std::vector<IoEventInfo> interests, Canceller canceller)
        : IoAwaitableBase(monitor, std::move(interests), std::move(canceller)) { }
};

/** `co_await Monitor::whenAny(...)` -> every descriptor found ready (at least one). */
class IoWhenAnyAwaitable : public detail::IoAwaitableBase {
public:
    std::vector<IoEventInfo> await_resume();

private:
    friend class Monitor;
    IoWhenAnyAwaitable(Monitor& monitor, std::vector<IoEventInfo> interests, Canceller canceller)
        : IoAwaitableBase(monitor, std::move(interests), std::move(canceller)) { }
};

/**
 * Asynchronous I/O readiness monitor (a reactor).
 *
 * One monitor thread waits on a `MonitorBackend` (epoll / poll / ...); a ready
 * descriptor resumes its waiting coroutines *on the worker they suspended on*.
 * Waits are one-shot: after it resumes, issue a new wait for the next event.
 *
 * - Several coroutines may wait on the same descriptor (e.g. one reading, one writing).
 * - `IoError` / `IoHangup` are always reported, whatever was requested.
 * - Descriptors should be non-blocking; readiness is a hint, not a guarantee.
 * - Do not close a descriptor while waiting on it: call `cancel(fd)` first.
 */
class Monitor {
public:
    explicit Monitor(std::unique_ptr<MonitorBackend> backend = MonitorBackend::createDefault());
    ~Monitor();

    Monitor(const Monitor&) = delete;
    Monitor& operator=(const Monitor&) = delete;

    /** The process wide monitor used by the static helpers (never destroyed). */
    static Monitor& defaultMonitor();

    // --> static helpers on the default monitor.
    static IoWaitAwaitable wait(int fd, int events, Canceller canceller = { });
    static IoWhenAnyAwaitable whenAny(std::span<const int> fds, int events, Canceller canceller = { });
    static IoWhenAnyAwaitable whenAny(std::initializer_list<int> fds, int events, Canceller canceller = { });
    static IoWhenAnyAwaitable whenAny(std::vector<IoEventInfo> interests, Canceller canceller = { });

    // --> the same on this monitor.
    IoWaitAwaitable watch(int fd, int events, Canceller canceller = { });
    IoWhenAnyAwaitable watchAny(std::span<const int> fds, int events, Canceller canceller = { });
    IoWhenAnyAwaitable watchAny(std::vector<IoEventInfo> interests, Canceller canceller = { });

    /** Aborts every wait involving `fd` (they throw `OperationCanceled`). */
    void cancel(int fd);

    const char* backendName() const noexcept;

private:
    friend class detail::IoAwaitableBase;
    struct Impl;

    void attach(detail::IoWaiter* waiter);
    void abort(detail::IoWaiter* waiter);

    std::unique_ptr<Impl> impl_;
};

} // namespace taskpp
