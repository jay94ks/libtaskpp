#pragma once
// Task combinators: whenAll / whenAny over tasks, plus withTimeout.
// All names live in `taskpp`.
#include <taskpp/Exceptions.hpp>
#include <taskpp/TimeSpan.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Task.hpp>
#include <taskpp/core/Timer.hpp>
#include <taskpp/core/detail/Completion.hpp>

#include <atomic>
#include <coroutine>
#include <cstddef>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace taskpp {

/** Result of `whenAny` over a homogeneous set: winner index + value. */
template<typename T>
struct WhenAnyResult {
    std::size_t index;
    T value;
};

/** Result of `whenAny` over `Task<void>`: winner index only. */
struct WhenAnyVoidResult {
    std::size_t index;
};

namespace detail {

// Self-destroying runner: owns its frame, keeps Shared alive, reports back.
struct RunnerPromise {
    struct Runner {
        struct promise_type {
            Runner get_return_object() noexcept {
                return Runner { std::coroutine_handle<promise_type>::from_promise(*this) };
            }
            std::suspend_always initial_suspend() const noexcept { return { }; }
            std::suspend_never final_suspend() const noexcept { return { }; }
            void return_void() const noexcept { }
            void unhandled_exception() const noexcept { std::terminate(); }
        };
        std::coroutine_handle<promise_type> handle;
    };
};

template<typename T>
struct WhenVectorShared {
    std::mutex mutex;
    std::vector<std::optional<T>> values;
    std::vector<std::exception_ptr> errors;
    std::atomic<std::size_t> remaining;
    std::atomic<bool> won { false };      // for whenAny: first finisher wins.
    std::atomic<bool> abandoned { false };// parent destroyed while suspended.
    Completion completion;
    std::coroutine_handle<> parent;
    bool forAny = false;
    std::exception_ptr firstError;
    WhenAnyResult<T> anyResult;
    bool hasAnyResult = false;

    explicit WhenVectorShared(std::size_t n)
        : values(n), errors(n), remaining(n) { }
};

struct WhenVectorVoidShared {
    std::mutex mutex;
    std::size_t remaining;
    std::exception_ptr firstError;
    std::atomic<bool> won { false };
    std::atomic<bool> abandoned { false };
    Completion completion;
    std::coroutine_handle<> parent;
    bool forAny = false;
    std::size_t anyIndex = 0;
    bool hasAnyResult = false;

    explicit WhenVectorVoidShared(std::size_t n) : remaining(n) { }
};

// --- runners for vector<T> ---------------------------------------------

template<typename T>
RunnerPromise::Runner runWhenVector(std::shared_ptr<WhenVectorShared<T>> shared,
    Task<T> task, std::size_t index) {
    try {
        T value = co_await std::move(task);
        bool last = false;
        bool win = false;
        {
            std::lock_guard lock(shared->mutex);
            shared->values[index].emplace(std::move(value));
            if (shared->forAny) {
                if (!shared->won.exchange(true)) {
                    shared->anyResult = WhenAnyResult<T> { index, std::move(*shared->values[index]) };
                    shared->hasAnyResult = true;
                    win = true;
                }
            }
            else {
                if (shared->remaining.fetch_sub(1) == 1) {
                    last = true;
                }
            }
        }
        if (win || last) {
            if (!shared->abandoned.load(std::memory_order_acquire)) {
                shared->completion.tryComplete();
            }
        }
    }
    catch (...) {
        bool last = false;
        bool win = false;
        {
            std::lock_guard lock(shared->mutex);
            shared->errors[index] = std::current_exception();
            if (shared->forAny) {
                if (!shared->won.exchange(true)) {
                    shared->firstError = shared->errors[index];
                    win = true;
                }
            }
            else {
                if (!shared->firstError) {
                    shared->firstError = shared->errors[index];
                }
                if (shared->remaining.fetch_sub(1) == 1) {
                    last = true;
                }
            }
        }
        if (win || last) {
            if (!shared->abandoned.load(std::memory_order_acquire)) {
                shared->completion.tryComplete();
            }
        }
    }
}

RunnerPromise::Runner runWhenVectorVoid(std::shared_ptr<WhenVectorVoidShared> shared,
    Task<void> task, std::size_t index) {
    try {
        co_await std::move(task);
        bool last = false;
        bool win = false;
        {
            std::lock_guard lock(shared->mutex);
            if (shared->forAny) {
                if (!shared->won.exchange(true)) {
                    shared->anyIndex = index;
                    shared->hasAnyResult = true;
                    win = true;
                }
            }
            else if (--shared->remaining == 0) {
                last = true;
            }
        }
        if (win || last) {
            if (!shared->abandoned.load(std::memory_order_acquire)) {
                shared->completion.tryComplete();
            }
        }
    }
    catch (...) {
        bool last = false;
        bool win = false;
        {
            std::lock_guard lock(shared->mutex);
            if (!shared->firstError) {
                shared->firstError = std::current_exception();
            }
            if (shared->forAny) {
                if (!shared->won.exchange(true)) {
                    shared->anyIndex = index;
                    win = true;
                }
            }
            else if (--shared->remaining == 0) {
                last = true;
            }
        }
        if (win || last) {
            if (!shared->abandoned.load(std::memory_order_acquire)) {
                shared->completion.tryComplete();
            }
        }
    }
}

} // namespace detail

namespace detail {

template<typename T>
class WhenVectorAwaitable {
public:
    WhenVectorAwaitable(std::vector<Task<T>> tasks, bool forAny, Canceller canceller)
        : tasks_(std::move(tasks)), forAny_(forAny), canceller_(std::move(canceller)) { }

    WhenVectorAwaitable(const WhenVectorAwaitable&) = delete;
    WhenVectorAwaitable& operator=(const WhenVectorAwaitable&) = delete;
    ~WhenVectorAwaitable() {
        if (shared_) {
            shared_->abandoned.store(true, std::memory_order_release);
        }
    }

    bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> handle) {
        if (tasks_.empty()) {
            empty_ = true;
            return false;
        }
        if (canceller_.isTriggered()) {
            canceled_ = true;
            return false;
        }
        shared_ = std::make_shared<WhenVectorShared<T>>(tasks_.size());
        shared_->forAny = forAny_;
        shared_->completion.prepare(handle);
        // Start every runner inline: each runs until its first suspension,
        // capturing worker affinity via ResumeTarget at that point.
        for (std::size_t i = 0; i < tasks_.size(); ++i) {
            auto runner = runWhenVector<T>(shared_, std::move(tasks_[i]), i);
            runner.handle.resume();
        }
        tasks_.clear();
        tasks_.shrink_to_fit();
        if (canceller_.canBeTriggered()) {
            registration_ = canceller_.onTriggered([shared = shared_] {
                if (!shared->abandoned.load(std::memory_order_acquire)) {
                    shared->completion.tryComplete();
                }
            });
        }
        return shared_->completion.finishSuspend();
    }

    std::shared_ptr<WhenVectorShared<T>> await_resume() {
        registration_.reset();
        if (canceled_) {
            throw OperationCanceled();
        }
        if (!shared_) {
            return nullptr;
        }
        // Cancellation raced with completion: if the canceller fired but a
        // result is already available, prefer the result for whenAny; for
        // whenAll require all tasks (otherwise report cancellation).
        if (canceller_.isTriggered()) {
            if (forAny_) {
                std::lock_guard lock(shared_->mutex);
                if (!shared_->hasAnyResult && !shared_->firstError) {
                    throw OperationCanceled();
                }
            }
            else {
                // whenAll: if not everything finished, cancellation wins.
                if (shared_->remaining.load() != 0) {
                    throw OperationCanceled();
                }
            }
        }
        return shared_;
    }

private:
    std::vector<Task<T>> tasks_;
    bool forAny_;
    Canceller canceller_;
    std::shared_ptr<WhenVectorShared<T>> shared_;
    CancelRegistration registration_;
    bool empty_ = false;
    bool canceled_ = false;
};

class WhenVectorVoidAwaitable {
public:
    WhenVectorVoidAwaitable(std::vector<Task<void>> tasks, bool forAny, Canceller canceller)
        : tasks_(std::move(tasks)), forAny_(forAny), canceller_(std::move(canceller)) { }

    WhenVectorVoidAwaitable(const WhenVectorVoidAwaitable&) = delete;
    WhenVectorVoidAwaitable& operator=(const WhenVectorVoidAwaitable&) = delete;
    ~WhenVectorVoidAwaitable() {
        if (shared_) {
            shared_->abandoned.store(true, std::memory_order_release);
        }
    }

    bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> handle) {
        if (tasks_.empty()) {
            return false;
        }
        if (canceller_.isTriggered()) {
            canceled_ = true;
            return false;
        }
        shared_ = std::make_shared<WhenVectorVoidShared>(tasks_.size());
        shared_->forAny = forAny_;
        shared_->completion.prepare(handle);
        for (std::size_t i = 0; i < tasks_.size(); ++i) {
            auto runner = runWhenVectorVoid(shared_, std::move(tasks_[i]), i);
            runner.handle.resume();
        }
        tasks_.clear();
        tasks_.shrink_to_fit();
        if (canceller_.canBeTriggered()) {
            registration_ = canceller_.onTriggered([shared = shared_] {
                if (!shared->abandoned.load(std::memory_order_acquire)) {
                    shared->completion.tryComplete();
                }
            });
        }
        return shared_->completion.finishSuspend();
    }

    std::shared_ptr<WhenVectorVoidShared> await_resume() {
        registration_.reset();
        if (canceled_) {
            throw OperationCanceled();
        }
        if (!shared_) {
            return nullptr;
        }
        if (canceller_.isTriggered()) {
            if (forAny_) {
                std::lock_guard lock(shared_->mutex);
                if (!shared_->hasAnyResult && !shared_->firstError) {
                    throw OperationCanceled();
                }
            }
            else if (shared_->remaining != 0) {
                throw OperationCanceled();
            }
        }
        return shared_;
    }

private:
    std::vector<Task<void>> tasks_;
    bool forAny_;
    Canceller canceller_;
    std::shared_ptr<WhenVectorVoidShared> shared_;
    CancelRegistration registration_;
    bool canceled_ = false;
};

} // namespace detail

// ---------------------------------------------------------------- whenAll

/** `co_await whenAll(tasks)` -> results in order; throws the first error. */
template<typename T> requires (!std::is_void_v<T>)
Task<std::vector<T>> whenAll(std::vector<Task<T>> tasks, Canceller canceller = { }) {
    detail::WhenVectorAwaitable<T> awaitable(std::move(tasks), false, std::move(canceller));
    auto shared = co_await awaitable;
    if (!shared) {
        co_return std::vector<T> { };
    }
    if (shared->firstError) {
        std::rethrow_exception(shared->firstError);
    }
    std::vector<T> out;
    out.reserve(shared->values.size());
    for (auto& v : shared->values) {
        out.emplace_back(std::move(*v));
    }
    co_return out;
}

/** `co_await whenAll(tasks)` for `Task<void>`: completes when all complete. */
inline Task<void> whenAll(std::vector<Task<void>> tasks, Canceller canceller = { }) {
    detail::WhenVectorVoidAwaitable awaitable(std::move(tasks), false, std::move(canceller));
    auto shared = co_await awaitable;
    if (shared && shared->firstError) {
        std::rethrow_exception(shared->firstError);
    }
    co_return;
}

// Variadic whenAll -> tuple (void maps to std::monostate).
namespace detail {

template<typename T>
struct WhenValue {
    using type = T;
};
template<>
struct WhenValue<void> {
    using type = std::monostate;
};

template<typename... Ts>
struct WhenTupleShared {
    std::mutex mutex;
    std::tuple<std::optional<typename WhenValue<Ts>::type>...> values;
    std::exception_ptr firstError;
    std::atomic<std::size_t> remaining { sizeof...(Ts) };
    std::atomic<bool> abandoned { false };
    Completion completion;

    WhenTupleShared() = default;
};

template<std::size_t I, typename... Ts>
RunnerPromise::Runner runWhenTuple(std::shared_ptr<WhenTupleShared<Ts...>> shared,
    Task<std::tuple_element_t<I, std::tuple<Ts...>>> task) {
    using Raw = std::tuple_element_t<I, std::tuple<Ts...>>;
    using Val = typename WhenValue<Raw>::type;
    try {
        if constexpr (std::is_void_v<Raw>) {
            co_await std::move(task);
            {
                std::lock_guard lock(shared->mutex);
                std::get<I>(shared->values).emplace(Val { });
            }
        }
        else {
            Val v = co_await std::move(task);
            {
                std::lock_guard lock(shared->mutex);
                std::get<I>(shared->values).emplace(std::move(v));
            }
        }
        if (shared->remaining.fetch_sub(1) == 1) {
            if (!shared->abandoned.load(std::memory_order_acquire)) {
                shared->completion.tryComplete();
            }
        }
    }
    catch (...) {
        {
            std::lock_guard lock(shared->mutex);
            if (!shared->firstError) {
                shared->firstError = std::current_exception();
            }
        }
        if (shared->remaining.fetch_sub(1) == 1) {
            if (!shared->abandoned.load(std::memory_order_acquire)) {
                shared->completion.tryComplete();
            }
        }
    }
}

template<typename... Ts, std::size_t... Is>
void startWhenTuple(std::shared_ptr<WhenTupleShared<Ts...>> shared,
    std::tuple<Task<Ts>...> tasks, std::index_sequence<Is...>) {
    (runWhenTuple<Is, Ts...>(shared, std::move(std::get<Is>(tasks))).handle.resume(), ...);
}

template<typename... Ts>
class WhenTupleAwaitable {
public:
    explicit WhenTupleAwaitable(std::tuple<Task<Ts>...> tasks, Canceller canceller)
        : tasks_(std::move(tasks)), canceller_(std::move(canceller)) { }

    WhenTupleAwaitable(const WhenTupleAwaitable&) = delete;
    WhenTupleAwaitable& operator=(const WhenTupleAwaitable&) = delete;
    ~WhenTupleAwaitable() {
        if (shared_) {
            shared_->abandoned.store(true, std::memory_order_release);
        }
    }

    bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> handle) {
        if constexpr (sizeof...(Ts) == 0) {
            return false;
        }
        if (canceller_.isTriggered()) {
            canceled_ = true;
            return false;
        }
        shared_ = std::make_shared<WhenTupleShared<Ts...>>();
        shared_->completion.prepare(handle);
        auto tasks = std::move(*tasks_);
        tasks_.reset();
        startWhenTuple<Ts...>(shared_, std::move(tasks), std::index_sequence_for<Ts...> { });
        if (canceller_.canBeTriggered()) {
            registration_ = canceller_.onTriggered([shared = shared_] {
                if (!shared->abandoned.load(std::memory_order_acquire)) {
                    shared->completion.tryComplete();
                }
            });
        }
        return shared_->completion.finishSuspend();
    }

    std::shared_ptr<WhenTupleShared<Ts...>> await_resume() {
        registration_.reset();
        if (canceled_) {
            throw OperationCanceled();
        }
        if (!shared_) {
            return std::make_shared<WhenTupleShared<Ts...>>();
        }
        if (canceller_.isTriggered() && shared_->remaining.load() != 0) {
            throw OperationCanceled();
        }
        return shared_;
    }

private:
    std::optional<std::tuple<Task<Ts>...>> tasks_;
    Canceller canceller_;
    std::shared_ptr<WhenTupleShared<Ts...>> shared_;
    CancelRegistration registration_;
    bool canceled_ = false;
};

} // namespace detail

/** `co_await whenAll(t1, t2, ...)` -> tuple of results (`void` -> `std::monostate`). */
template<typename... Ts>
Task<std::tuple<typename detail::WhenValue<Ts>::type...>> whenAll(Task<Ts>... tasks) {
    detail::WhenTupleAwaitable<Ts...> awaitable(std::make_tuple(std::move(tasks)...), { });
    auto shared = co_await awaitable;
    if (shared->firstError) {
        std::rethrow_exception(shared->firstError);
    }
    co_return std::apply([](auto&... opts) {
        return std::make_tuple(std::move(*opts)...);
    }, shared->values);
}

/** Canceller-aware variadic `whenAll`. */
template<typename... Ts>
Task<std::tuple<typename detail::WhenValue<Ts>::type...>> whenAllWithCanceller(
    Canceller canceller, Task<Ts>... tasks) {
    detail::WhenTupleAwaitable<Ts...> awaitable(std::make_tuple(std::move(tasks)...), std::move(canceller));
    auto shared = co_await awaitable;
    if (shared->firstError) {
        std::rethrow_exception(shared->firstError);
    }
    co_return std::apply([](auto&... opts) {
        return std::make_tuple(std::move(*opts)...);
    }, shared->values);
}

// ---------------------------------------------------------------- whenAny

/** `co_await whenAny(tasks)` -> `{ index, value }` of the first finisher. */
template<typename T> requires (!std::is_void_v<T>)
Task<WhenAnyResult<T>> whenAny(std::vector<Task<T>> tasks, Canceller canceller = { }) {
    detail::WhenVectorAwaitable<T> awaitable(std::move(tasks), true, std::move(canceller));
    auto shared = co_await awaitable;
    if (!shared) {
        throw std::invalid_argument("whenAny requires at least one task.");
    }
    // Losers keep running in the background until they finish; their frames
    // stay alive via the shared state so nothing dangles.
    if (shared->firstError) {
        std::rethrow_exception(shared->firstError);
    }
    if (!shared->hasAnyResult) {
        throw OperationCanceled();
    }
    co_return std::move(shared->anyResult);
}

/** `co_await whenAny(tasks)` for `Task<void>` -> winner index. */
inline Task<std::size_t> whenAny(std::vector<Task<void>> tasks, Canceller canceller = { }) {
    detail::WhenVectorVoidAwaitable awaitable(std::move(tasks), true, std::move(canceller));
    auto shared = co_await awaitable;
    if (!shared) {
        throw std::invalid_argument("whenAny requires at least one task.");
    }
    if (shared->firstError && !shared->hasAnyResult) {
        std::rethrow_exception(shared->firstError);
    }
    co_return shared->anyIndex;
}

namespace detail {

template<typename... Ts>
struct WhenAnyVariantShared {
    std::mutex mutex;
    std::optional<std::variant<typename WhenValue<Ts>::type...>> result;
    std::exception_ptr firstError;
    std::atomic<bool> won { false };
    std::atomic<bool> abandoned { false };
    Completion completion;
};

template<std::size_t I, typename... Ts>
RunnerPromise::Runner runWhenAnyTuple(std::shared_ptr<WhenAnyVariantShared<Ts...>> shared,
    Task<std::tuple_element_t<I, std::tuple<Ts...>>> task) {
    using Raw = std::tuple_element_t<I, std::tuple<Ts...>>;
    using Val = typename WhenValue<Raw>::type;
    try {
        std::optional<Val> value;
        if constexpr (std::is_void_v<Raw>) {
            co_await std::move(task);
            value.emplace(Val { });
        }
        else {
            value.emplace(co_await std::move(task));
        }
        {
            std::lock_guard lock(shared->mutex);
            if (!shared->won.exchange(true)) {
                shared->result.emplace(std::variant<typename WhenValue<Ts>::type...>(
                    std::in_place_index<I>, std::move(*value)));
            }
            else {
                co_return;
            }
        }
        if (!shared->abandoned.load(std::memory_order_acquire)) {
            shared->completion.tryComplete();
        }
    }
    catch (...) {
        {
            std::lock_guard lock(shared->mutex);
            if (!shared->won.exchange(true)) {
                shared->firstError = std::current_exception();
            }
            else {
                co_return;
            }
        }
        if (!shared->abandoned.load(std::memory_order_acquire)) {
            shared->completion.tryComplete();
        }
    }
}

template<typename... Ts, std::size_t... Is>
void startWhenAnyTuple(std::shared_ptr<WhenAnyVariantShared<Ts...>> shared,
    std::tuple<Task<Ts>...> tasks, std::index_sequence<Is...>) {
    (runWhenAnyTuple<Is, Ts...>(shared, std::move(std::get<Is>(tasks))).handle.resume(), ...);
}

template<typename... Ts>
class WhenAnyTupleAwaitable {
public:
    explicit WhenAnyTupleAwaitable(std::tuple<Task<Ts>...> tasks, Canceller canceller)
        : tasks_(std::move(tasks)), canceller_(std::move(canceller)) { }

    WhenAnyTupleAwaitable(const WhenAnyTupleAwaitable&) = delete;
    WhenAnyTupleAwaitable& operator=(const WhenAnyTupleAwaitable&) = delete;
    ~WhenAnyTupleAwaitable() {
        if (shared_) {
            shared_->abandoned.store(true, std::memory_order_release);
        }
    }

    bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> handle) {
        static_assert(sizeof...(Ts) > 0, "whenAny requires at least one task.");
        if (canceller_.isTriggered()) {
            canceled_ = true;
            return false;
        }
        shared_ = std::make_shared<WhenAnyVariantShared<Ts...>>();
        shared_->completion.prepare(handle);
        auto tasks = std::move(*tasks_);
        tasks_.reset();
        startWhenAnyTuple<Ts...>(shared_, std::move(tasks), std::index_sequence_for<Ts...> { });
        if (canceller_.canBeTriggered()) {
            registration_ = canceller_.onTriggered([shared = shared_] {
                if (!shared->abandoned.load(std::memory_order_acquire)) {
                    shared->completion.tryComplete();
                }
            });
        }
        return shared_->completion.finishSuspend();
    }

    std::shared_ptr<WhenAnyVariantShared<Ts...>> await_resume() {
        registration_.reset();
        if (canceled_) {
            throw OperationCanceled();
        }
        if (canceller_.isTriggered()) {
            std::lock_guard lock(shared_->mutex);
            if (!shared_->result && !shared_->firstError) {
                throw OperationCanceled();
            }
        }
        return shared_;
    }

private:
    std::optional<std::tuple<Task<Ts>...>> tasks_;
    Canceller canceller_;
    std::shared_ptr<WhenAnyVariantShared<Ts...>> shared_;
    CancelRegistration registration_;
    bool canceled_ = false;
};

} // namespace detail

/**
 * `co_await whenAny(t1, t2, ...)` -> variant of the first finisher
 * (`variant::index()` is the winner; `void` maps to `std::monostate`).
 */
template<typename... Ts>
Task<std::variant<typename detail::WhenValue<Ts>::type...>> whenAny(Task<Ts>... tasks) {
    detail::WhenAnyTupleAwaitable<Ts...> awaitable(std::make_tuple(std::move(tasks)...), { });
    auto shared = co_await awaitable;
    if (shared->firstError) {
        std::rethrow_exception(shared->firstError);
    }
    if (!shared->result) {
        throw OperationCanceled();
    }
    co_return std::move(*shared->result);
}

/** Canceller-aware variadic `whenAny`. */
template<typename... Ts>
Task<std::variant<typename detail::WhenValue<Ts>::type...>> whenAnyWithCanceller(
    Canceller canceller, Task<Ts>... tasks) {
    detail::WhenAnyTupleAwaitable<Ts...> awaitable(std::make_tuple(std::move(tasks)...), std::move(canceller));
    auto shared = co_await awaitable;
    if (shared->firstError) {
        std::rethrow_exception(shared->firstError);
    }
    if (!shared->result) {
        throw OperationCanceled();
    }
    co_return std::move(*shared->result);
}

// ------------------------------------------------------------ withTimeout

namespace detail {

template<typename T>
struct TimeoutShared {
    std::mutex mutex;
    std::optional<T> value;
    std::exception_ptr error;
    std::atomic<bool> won { false };
    std::atomic<bool> abandoned { false };
    Completion completion;
    TimerService::Id timerId = 0;
};

struct TimeoutVoidShared {
    std::mutex mutex;
    std::exception_ptr error;
    bool done = false;
    std::atomic<bool> won { false };
    std::atomic<bool> abandoned { false };
    Completion completion;
    TimerService::Id timerId = 0;
};

template<typename T>
RunnerPromise::Runner runWithTimeout(std::shared_ptr<TimeoutShared<T>> shared, Task<T> task) {
    try {
        T value = co_await std::move(task);
        {
            std::lock_guard lock(shared->mutex);
            if (shared->won.exchange(true)) {
                co_return;
            }
            shared->value.emplace(std::move(value));
        }
        if (shared->timerId) {
            TimerService::instance().cancel(shared->timerId);
        }
        if (!shared->abandoned.load(std::memory_order_acquire)) {
            shared->completion.tryComplete();
        }
    }
    catch (...) {
        {
            std::lock_guard lock(shared->mutex);
            if (shared->won.exchange(true)) {
                co_return;
            }
            shared->error = std::current_exception();
        }
        if (shared->timerId) {
            TimerService::instance().cancel(shared->timerId);
        }
        if (!shared->abandoned.load(std::memory_order_acquire)) {
            shared->completion.tryComplete();
        }
    }
}

inline RunnerPromise::Runner runWithTimeoutVoid(std::shared_ptr<TimeoutVoidShared> shared, Task<void> task) {
    try {
        co_await std::move(task);
        {
            std::lock_guard lock(shared->mutex);
            if (shared->won.exchange(true)) {
                co_return;
            }
            shared->done = true;
        }
        if (shared->timerId) {
            TimerService::instance().cancel(shared->timerId);
        }
        if (!shared->abandoned.load(std::memory_order_acquire)) {
            shared->completion.tryComplete();
        }
    }
    catch (...) {
        {
            std::lock_guard lock(shared->mutex);
            if (shared->won.exchange(true)) {
                co_return;
            }
            shared->error = std::current_exception();
        }
        if (shared->timerId) {
            TimerService::instance().cancel(shared->timerId);
        }
        if (!shared->abandoned.load(std::memory_order_acquire)) {
            shared->completion.tryComplete();
        }
    }
}

template<typename T>
class TimeoutAwaitable {
public:
    TimeoutAwaitable(Task<T> task, TimeSpan timeout, Canceller canceller)
        : task_(std::move(task)), timeout_(timeout), canceller_(std::move(canceller)) { }

    TimeoutAwaitable(const TimeoutAwaitable&) = delete;
    TimeoutAwaitable& operator=(const TimeoutAwaitable&) = delete;
    ~TimeoutAwaitable() {
        if (shared_) {
            shared_->abandoned.store(true, std::memory_order_release);
            if (shared_->timerId) {
                TimerService::instance().cancel(shared_->timerId);
            }
        }
    }

    bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> handle) {
        if (canceller_.isTriggered()) {
            canceled_ = true;
            return false;
        }
        shared_ = std::make_shared<TimeoutShared<T>>();
        shared_->completion.prepare(handle);
        if (timeout_ <= TimeSpan::zero()) {
            timedOut_ = true;
            return false;
        }
        auto runner = runWithTimeout<T>(shared_, std::move(*task_));
        runner.handle.resume();
        shared_->timerId = TimerService::instance().scheduleAfter(timeout_, [shared = shared_] {
            {
                std::lock_guard lock(shared->mutex);
                if (shared->won.exchange(true)) {
                    return;
                }
            }
            if (!shared->abandoned.load(std::memory_order_acquire)) {
                shared->completion.tryComplete();
            }
        });
        if (canceller_.canBeTriggered()) {
            registration_ = canceller_.onTriggered([shared = shared_] {
                {
                    std::lock_guard lock(shared->mutex);
                    if (shared->won.exchange(true)) {
                        return;
                    }
                    shared->error = std::make_exception_ptr(OperationCanceled());
                }
                if (shared->timerId) {
                    TimerService::instance().cancel(shared->timerId);
                }
                if (!shared->abandoned.load(std::memory_order_acquire)) {
                    shared->completion.tryComplete();
                }
            });
        }
        return shared_->completion.finishSuspend();
    }

    T await_resume() {
        registration_.reset();
        if (canceled_) {
            throw OperationCanceled();
        }
        if (timedOut_) {
            throw Timeout();
        }
        if (shared_->timerId) {
            TimerService::instance().cancel(shared_->timerId);
        }
        if (shared_->error) {
            std::rethrow_exception(shared_->error);
        }
        if (!shared_->value) {
            // Timer won the race.
            throw Timeout();
        }
        return std::move(*shared_->value);
    }

private:
    std::optional<Task<T>> task_;
    TimeSpan timeout_;
    Canceller canceller_;
    std::shared_ptr<TimeoutShared<T>> shared_;
    CancelRegistration registration_;
    bool canceled_ = false;
    bool timedOut_ = false;
};

class TimeoutVoidAwaitable {
public:
    TimeoutVoidAwaitable(Task<void> task, TimeSpan timeout, Canceller canceller)
        : task_(std::move(task)), timeout_(timeout), canceller_(std::move(canceller)) { }

    TimeoutVoidAwaitable(const TimeoutVoidAwaitable&) = delete;
    TimeoutVoidAwaitable& operator=(const TimeoutVoidAwaitable&) = delete;
    ~TimeoutVoidAwaitable() {
        if (shared_) {
            shared_->abandoned.store(true, std::memory_order_release);
            if (shared_->timerId) {
                TimerService::instance().cancel(shared_->timerId);
            }
        }
    }

    bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> handle) {
        if (canceller_.isTriggered()) {
            canceled_ = true;
            return false;
        }
        shared_ = std::make_shared<TimeoutVoidShared>();
        shared_->completion.prepare(handle);
        if (timeout_ <= TimeSpan::zero()) {
            timedOut_ = true;
            return false;
        }
        auto runner = runWithTimeoutVoid(shared_, std::move(*task_));
        runner.handle.resume();
        shared_->timerId = TimerService::instance().scheduleAfter(timeout_, [shared = shared_] {
            {
                std::lock_guard lock(shared->mutex);
                if (shared->won.exchange(true)) {
                    return;
                }
            }
            if (!shared->abandoned.load(std::memory_order_acquire)) {
                shared->completion.tryComplete();
            }
        });
        if (canceller_.canBeTriggered()) {
            registration_ = canceller_.onTriggered([shared = shared_] {
                {
                    std::lock_guard lock(shared->mutex);
                    if (shared->won.exchange(true)) {
                        return;
                    }
                    shared->error = std::make_exception_ptr(OperationCanceled());
                }
                if (shared->timerId) {
                    TimerService::instance().cancel(shared->timerId);
                }
                if (!shared->abandoned.load(std::memory_order_acquire)) {
                    shared->completion.tryComplete();
                }
            });
        }
        return shared_->completion.finishSuspend();
    }

    void await_resume() {
        registration_.reset();
        if (canceled_) {
            throw OperationCanceled();
        }
        if (timedOut_) {
            throw Timeout();
        }
        if (shared_->timerId) {
            TimerService::instance().cancel(shared_->timerId);
        }
        if (shared_->error) {
            std::rethrow_exception(shared_->error);
        }
        if (!shared_->done) {
            throw Timeout();
        }
    }

private:
    std::optional<Task<void>> task_;
    TimeSpan timeout_;
    Canceller canceller_;
    std::shared_ptr<TimeoutVoidShared> shared_;
    CancelRegistration registration_;
    bool canceled_ = false;
    bool timedOut_ = false;
};

} // namespace detail

/**
 * Runs `task` with a deadline: returns its result, or throws `Timeout`
 * (which derives from `OperationCanceled`) when `timeout` expires first.
 * The loser keeps running in the background until it finishes, so no frame
 * is destroyed while suspended. Pass a `Canceller` to abort both sides.
 */
template<typename T> requires (!std::is_void_v<T>)
Task<T> withTimeout(Task<T> task, TimeSpan timeout, Canceller canceller = { }) {
    detail::TimeoutAwaitable<T> awaitable(std::move(task), timeout, std::move(canceller));
    co_return co_await awaitable;
}

inline Task<void> withTimeout(Task<void> task, TimeSpan timeout, Canceller canceller = { }) {
    detail::TimeoutVoidAwaitable awaitable(std::move(task), timeout, std::move(canceller));
    co_await awaitable;
    co_return;
}

} // namespace taskpp
