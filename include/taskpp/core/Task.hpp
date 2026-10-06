#pragma once
#include <taskpp/Config.hpp>

#include <concepts>
#include <coroutine>
#include <exception>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <variant>

namespace taskpp {

template<typename T = void>
class Task;

namespace detail {

class TaskPromiseBase {
public:
    struct FinalAwaiter {
        bool await_ready() const noexcept { return false; }

        template<typename Promise>
        std::coroutine_handle<> await_suspend(std::coroutine_handle<Promise> self) noexcept {
            // symmetric transfer back to whoever awaited us.
            if (auto next = self.promise().continuation_) {
                return next;
            }
            return std::noop_coroutine();
        }

        void await_resume() const noexcept { }
    };

    // tasks are lazy: nothing runs until awaited or handed to a worker.
    std::suspend_always initial_suspend() const noexcept { return { }; }
    FinalAwaiter final_suspend() const noexcept { return { }; }

    void setContinuation(std::coroutine_handle<> next) noexcept { continuation_ = next; }

private:
    std::coroutine_handle<> continuation_;
};

template<typename T>
class TaskPromise : public TaskPromiseBase {
public:
    Task<T> get_return_object() noexcept;

    void unhandled_exception() noexcept { result_.template emplace<2>(std::current_exception()); }

    template<typename U = T> requires std::constructible_from<T, U&&>
    void return_value(U&& value) noexcept(std::is_nothrow_constructible_v<T, U&&>) {
        result_.template emplace<1>(std::forward<U>(value));
    }

    T result() {
        if (result_.index() == 2) {
            std::rethrow_exception(std::get<2>(result_));
        }

        if (result_.index() != 1) {
            throw std::logic_error("the task has no result (not completed or already consumed).");
        }

        return std::move(std::get<1>(result_));
    }

private:
    std::variant<std::monostate, T, std::exception_ptr> result_;
};

template<>
class TaskPromise<void> : public TaskPromiseBase {
public:
    Task<void> get_return_object() noexcept;

    void unhandled_exception() noexcept { error_ = std::current_exception(); }
    void return_void() const noexcept { }

    void result() {
        if (error_) {
            std::rethrow_exception(error_);
        }
    }

private:
    std::exception_ptr error_;
};

} // namespace detail

/**
 * A lazily started, single-consumer asynchronous operation that produces `T`.
 *
 * - The coroutine body does not run until the task is `co_await`ed, or handed to
 *   a `Worker` (`push`, `sync_wait`).
 * - `co_await`ing a task runs it inline on the awaiting thread (symmetric transfer).
 * - The task owns its coroutine frame: destroying a not-yet-started task destroys the frame.
 * - Exceptions thrown inside the body are rethrown from `co_await`.
 */
template<typename T>
class [[nodiscard]] Task {
    static_assert(!std::is_reference_v<T>, "Task<T&> is not supported; use Task<T*> or std::reference_wrapper.");

public:
    using promise_type = detail::TaskPromise<T>;
    using value_type = T;
    using handle_type = std::coroutine_handle<promise_type>;

    Task() noexcept = default;
    explicit Task(handle_type handle) noexcept : handle_(handle) { }

    Task(Task&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) { }
    Task& operator=(Task&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;

    ~Task() { reset(); }

    bool valid() const noexcept { return static_cast<bool>(handle_); }
    explicit operator bool() const noexcept { return valid(); }

    bool isDone() const noexcept { return handle_ && handle_.done(); }

    /** Gives up ownership of the coroutine frame. */
    handle_type release() noexcept { return std::exchange(handle_, nullptr); }

    auto operator co_await() & noexcept { return Awaiter { handle_ }; }
    auto operator co_await() && noexcept { return Awaiter { handle_ }; }

private:
    struct Awaiter {
        handle_type handle;

        bool await_ready() const noexcept { return !handle || handle.done(); }

        std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiter) noexcept {
            handle.promise().setContinuation(awaiter);
            return handle;
        }

        T await_resume() {
            if (!handle) {
                throw std::logic_error("awaiting an empty task.");
            }

            return handle.promise().result();
        }
    };

    void reset() noexcept {
        if (handle_) {
            handle_.destroy();
            handle_ = nullptr;
        }
    }

    handle_type handle_;
};

namespace detail {

template<typename T>
inline Task<T> TaskPromise<T>::get_return_object() noexcept {
    return Task<T>(std::coroutine_handle<TaskPromise<T>>::from_promise(*this));
}

inline Task<void> TaskPromise<void>::get_return_object() noexcept {
    return Task<void>(std::coroutine_handle<TaskPromise<void>>::from_promise(*this));
}

} // namespace detail
} // namespace taskpp
