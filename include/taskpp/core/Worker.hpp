#pragma once
#include <taskpp/TimeSpan.hpp>
#include <taskpp/core/Task.hpp>

#include <condition_variable>
#include <coroutine>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace taskpp {

class Worker;

namespace detail {

/** Counts tasks `push`ed to a worker; outlives the worker (shared with task frames). */
class TaskTracker {
public:
    using ExceptionHandler = std::function<void(std::exception_ptr)>;

    void add();
    void done();
    void wait();
    bool waitFor(TimeSpan timeout);
    std::size_t pending() const;

    void setHandler(ExceptionHandler handler);
    void report(std::exception_ptr error) noexcept;

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::size_t count_ = 0;
    ExceptionHandler handler_;
};

/** Self-destroying root coroutine used to run a `Task` "detached" on a worker. */
struct DetachedRoot {
    struct promise_type {
        DetachedRoot get_return_object() noexcept {
            return DetachedRoot { std::coroutine_handle<promise_type>::from_promise(*this) };
        }

        std::suspend_always initial_suspend() const noexcept { return { }; }
        std::suspend_never final_suspend() const noexcept { return { }; }
        void return_void() const noexcept { }
        void unhandled_exception() const noexcept { std::terminate(); }
    };

    std::coroutine_handle<promise_type> handle;
};

template<typename T>
DetachedRoot runDetached(Task<T> task, std::shared_ptr<TaskTracker> tracker) {
    try {
        co_await std::move(task);
    }
    catch (...) {
        tracker->report(std::current_exception());
    }

    tracker->done();
}

template<typename T>
class SyncState {
public:
    template<typename... Args>
    void setValue(Args&&... args) {
        std::lock_guard lock(mutex_);
        value_.emplace(std::forward<Args>(args)...);
        done_ = true;
        cv_.notify_all();   // notify under the lock: the waiter owns (and destroys) us.
    }

    void setException(std::exception_ptr error) noexcept {
        std::lock_guard lock(mutex_);
        error_ = std::move(error);
        done_ = true;
        cv_.notify_all();
    }

    T get() {
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [this] { return done_; });

        if (error_) {
            std::rethrow_exception(error_);
        }

        return std::move(*value_);
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    bool done_ = false;
    std::optional<T> value_;
    std::exception_ptr error_;
};

template<>
class SyncState<void> {
public:
    void setValue() {
        std::lock_guard lock(mutex_);
        done_ = true;
        cv_.notify_all();
    }

    void setException(std::exception_ptr error) noexcept {
        std::lock_guard lock(mutex_);
        error_ = std::move(error);
        done_ = true;
        cv_.notify_all();
    }

    void get() {
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [this] { return done_; });

        if (error_) {
            std::rethrow_exception(error_);
        }
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    bool done_ = false;
    std::exception_ptr error_;
};

template<typename T>
DetachedRoot runSync(Task<T> task, SyncState<T>* state) {
    try {
        if constexpr (std::is_void_v<T>) {
            co_await std::move(task);
            state->setValue();
        }
        else {
            state->setValue(co_await std::move(task));
        }
    }
    catch (...) {
        state->setException(std::current_exception());
    }
}

} // namespace detail

/**
 * An execution context for coroutines.
 *
 * Implementations only have to provide `schedule()`: "resume this handle on one of
 * your threads, soon". Everything else (push / wait / sync_wait / currentWorker)
 * is built on top of it.
 *
 * Workers must be owned by `std::shared_ptr` (e.g. `std::make_shared<ThreadedWorker>()`)
 * so that `currentWorker()` and resumption affinity work.
 */
class Worker : public std::enable_shared_from_this<Worker> {
public:
    using ExceptionHandler = detail::TaskTracker::ExceptionHandler;

    Worker();
    virtual ~Worker();

    Worker(const Worker&) = delete;
    Worker& operator=(const Worker&) = delete;

    /** The worker running the calling thread, or nullptr on a foreign thread. */
    static std::shared_ptr<Worker> currentWorker() noexcept;

    /** The process wide default worker: a `ThreadPooledWorker`, created on demand. */
    static std::shared_ptr<Worker> defaultWorker();

    /** Replaces the default worker (the previous one is released). */
    static void setDefaultWorker(std::shared_ptr<Worker> worker);

    /** true if the calling thread is running this worker. */
    bool isCurrent() const noexcept;

    /** Low level: resume `handle` on this worker. Must be thread-safe. */
    virtual void schedule(std::coroutine_handle<> handle) = 0;

    /**
     * Starts `task` on this worker and returns immediately (fire and forget).
     * An exception escaping the task goes to the unhandled exception handler.
     */
    template<typename T>
    void push(Task<T> task) {
        if (!task) {
            throw std::invalid_argument("cannot push an empty task.");
        }

        tracker_->add();
        auto root = detail::runDetached<T>(std::move(task), tracker_);

        try {
            schedule(root.handle);
        }
        catch (...) {
            root.handle.destroy();
            tracker_->done();
            throw;
        }
    }

    /**
     * Blocks until every task `push`ed so far (and pushed while waiting) completed.
     * Throws `std::logic_error` when called from this worker's own thread (deadlock).
     */
    void wait();

    /** `wait()` with a timeout; returns false on timeout. */
    bool waitFor(TimeSpan timeout);

    /** Number of `push`ed tasks that did not complete yet. */
    std::size_t pendingCount() const;

    /**
     * Runs `task` on this worker and blocks the calling thread until it completes,
     * returning its result or rethrowing its exception.
     * Throws `std::logic_error` when called from this worker's own thread (deadlock).
     */
    template<typename T>
    T sync_wait(Task<T> task) {
        if (!task) {
            throw std::invalid_argument("cannot wait for an empty task.");
        }

        if (isCurrent()) {
            throw std::logic_error("sync_wait() called on the worker's own thread would deadlock; use co_await.");
        }

        detail::SyncState<T> state;
        auto root = detail::runSync<T>(std::move(task), &state);

        try {
            schedule(root.handle);
        }
        catch (...) {
            root.handle.destroy();
            throw;
        }

        return state.get();
    }

    /** Handler for exceptions escaping `push`ed tasks. Default: print to stderr. */
    void setUnhandledExceptionHandler(ExceptionHandler handler);

    /** Awaitable that reschedules the awaiting coroutine on a worker. */
    class ScheduleAwaitable {
    public:
        explicit ScheduleAwaitable(std::shared_ptr<Worker> worker) noexcept : worker_(std::move(worker)) { }

        bool await_ready() const noexcept { return false; }

        void await_suspend(std::coroutine_handle<> handle) const {
            // keep a local strong ref: once scheduled, the awaiter may be destroyed
            // by the resumed coroutine before schedule() returns.
            auto worker = worker_;
            worker->schedule(handle);
        }

        void await_resume() const noexcept { }

    private:
        std::shared_ptr<Worker> worker_;
    };

    /** `co_await Worker::yield();` gives other tasks of the current worker a chance to run. */
    static ScheduleAwaitable yield();

    /** `co_await Worker::switchTo(w);` continues the coroutine on worker `w`. */
    static ScheduleAwaitable switchTo(std::shared_ptr<Worker> worker);

    /**
     * Marks the calling thread as running `worker` for the scope's lifetime.
     * For custom `Worker` implementations: wrap each `handle.resume()` with it.
     */
    class ExecutionScope {
    public:
        explicit ExecutionScope(Worker* worker) noexcept;
        ~ExecutionScope();

        ExecutionScope(const ExecutionScope&) = delete;
        ExecutionScope& operator=(const ExecutionScope&) = delete;

    private:
        Worker* previous_;
    };

private:
    std::shared_ptr<detail::TaskTracker> tracker_;
};

/**
 * `co_await yield();` — free-function spelling of `Worker::yield()` for
 * symmetry with `delay()`. Gives other tasks of the current worker a chance
 * to run; resumes on the same worker.
 */
inline Worker::ScheduleAwaitable yield() {
    return Worker::yield();
}

} // namespace taskpp
