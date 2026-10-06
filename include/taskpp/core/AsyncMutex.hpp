#pragma once
#include <taskpp/Exceptions.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/detail/Completion.hpp>

#include <coroutine>
#include <list>
#include <memory>
#include <mutex>
#include <optional>

namespace taskpp {

/**
 * An asynchronous mutex: `co_await m.lock(ct)` suspends (FIFO) until the lock
 * is free, then resumes on the worker it suspended on.
 *
 *     AsyncMutex m;
 *     {
 *         auto guard = co_await m.lock(ct);   // throws OperationCanceled
 *         // ... critical section ...
 *     }                                       // released here
 *
 * Only the coroutine holding the guard may unlock (via guard destruction or
 * `unlock()`). `tryLock()` never suspends.
 */
class AsyncMutex {
    struct Waiter {
        detail::Completion completion;
        bool linked = false;
        typename std::list<Waiter*>::iterator position;
        bool canceled = false;
        bool aborted = false;   // mutex destroyed while waiting.
    };

    struct State {
        std::mutex mutex;
        bool locked = false;
        std::list<Waiter*> waiters;
    };

public:
    class ScopedLock {
    public:
        ScopedLock() noexcept = default;
        ScopedLock(ScopedLock&& other) noexcept
            : state_(other.state_) { other.state_ = nullptr; }
        ScopedLock& operator=(ScopedLock&& other) noexcept {
            if (this != &other) {
                unlock();
                state_ = other.state_;
                other.state_ = nullptr;
            }
            return *this;
        }

        ScopedLock(const ScopedLock&) = delete;
        ScopedLock& operator=(const ScopedLock&) = delete;

        ~ScopedLock() { unlock(); }

        void unlock() noexcept {
            if (auto* state = state_) {
                state_ = nullptr;
                Waiter* next = nullptr;
                {
                    std::lock_guard lock(state->mutex);
                    if (!state->waiters.empty()) {
                        next = state->waiters.front();
                        state->waiters.pop_front();
                        next->linked = false;
                        // handoff: stays locked, ownership moves to `next`.
                    }
                    else {
                        state->locked = false;
                    }
                }
                if (next) {
                    next->completion.tryComplete();
                }
            }
        }

        bool owns() const noexcept { return state_ != nullptr; }
        explicit operator bool() const noexcept { return owns(); }

    private:
        friend class AsyncMutex;
        explicit ScopedLock(std::shared_ptr<State> state) noexcept
            : state_(state.get()), shared_(std::move(state)) { }

        // raw pointer for unlock(); shared_ptr keeps State alive while held.
        State* state_ = nullptr;
        std::shared_ptr<State> shared_;
    };

    class LockAwaitable {
    public:
        LockAwaitable(std::shared_ptr<State> state, Canceller canceller) noexcept
            : state_(std::move(state)), canceller_(std::move(canceller)) { }

        LockAwaitable(const LockAwaitable&) = delete;
        LockAwaitable& operator=(const LockAwaitable&) = delete;
        ~LockAwaitable() {
            // Destroyed while still queued (e.g. the awaiting task was
            // destroyed): unlink so a later unlock never touches us.
            if (waiter_.linked) {
                std::lock_guard lock(state_->mutex);
                if (waiter_.linked) {
                    state_->waiters.erase(waiter_.position);
                    waiter_.linked = false;
                }
            }
        }

        bool await_ready() const noexcept { return false; }

        bool await_suspend(std::coroutine_handle<> handle) {
            if (canceller_.isTriggered()) {
                waiter_.canceled = true;
                return false;
            }

            waiter_.completion.prepare(handle);
            {
                std::lock_guard lock(state_->mutex);
                if (!state_->locked) {
                    state_->locked = true;
                    return false;
                }
                waiter_.position = state_->waiters.insert(state_->waiters.end(), &waiter_);
                waiter_.linked = true;
            }

            if (canceller_.canBeTriggered()) {
                registration_ = canceller_.onTriggered([this] {
                    {
                        std::lock_guard lock(state_->mutex);
                        if (!waiter_.linked) {
                            return; // already handed the lock.
                        }
                        state_->waiters.erase(waiter_.position);
                        waiter_.linked = false;
                    }
                    waiter_.completion.tryComplete([this] { waiter_.canceled = true; });
                });
            }

            return waiter_.completion.finishSuspend();
        }

        ScopedLock await_resume() {
            registration_.reset();
            if (waiter_.aborted) {
                throw std::runtime_error("the mutex was destroyed while waiting.");
            }
            if (waiter_.canceled) {
                throw OperationCanceled();
            }
            return ScopedLock(state_);
        }

    private:
        std::shared_ptr<State> state_;
        Canceller canceller_;
        Waiter waiter_;
        CancelRegistration registration_;
    };

    AsyncMutex() : state_(std::make_shared<State>()) { }
    ~AsyncMutex() {
        // Wake pending waiters; they throw rather than hang forever.
        std::list<Waiter*> waiters;
        {
            std::lock_guard lock(state_->mutex);
            waiters.swap(state_->waiters);
            for (auto* w : waiters) {
                w->linked = false;
                w->aborted = true;
            }
        }
        for (auto* w : waiters) {
            w->completion.tryComplete();
        }
    }

    AsyncMutex(const AsyncMutex&) = delete;
    AsyncMutex& operator=(const AsyncMutex&) = delete;

    LockAwaitable lock(Canceller canceller = { }) {
        return LockAwaitable(state_, std::move(canceller));
    }

    /** Tries to take the lock without suspending. */
    std::optional<ScopedLock> tryLock() {
        std::lock_guard lock(state_->mutex);
        if (state_->locked) {
            return std::nullopt;
        }
        state_->locked = true;
        return std::optional<ScopedLock>(ScopedLock(state_));
    }

    bool isLocked() const {
        std::lock_guard lock(state_->mutex);
        return state_->locked;
    }

private:
    std::shared_ptr<State> state_;
};

} // namespace taskpp
