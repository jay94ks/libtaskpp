#pragma once
#include <taskpp/Exceptions.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/detail/Completion.hpp>

#include <coroutine>
#include <cstddef>
#include <deque>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

namespace taskpp {

/**
 * A multi-producer / multi-consumer queue whose consumers `co_await` items.
 *
 *     AsyncQueue<int> queue;
 *     queue.push(1);                       // any thread
 *     int v = co_await queue.wait(ct);     // in a task; throws OperationCanceled / QueueClosed
 *
 * Waiters are served in FIFO order; a waiter resumes on the worker it suspended on.
 */
template<typename T>
class AsyncQueue {
    struct Waiter {
        detail::Completion completion;
        std::optional<T> value;
        bool canceled = false;
        bool closed = false;
        bool linked = false;
        typename std::list<Waiter*>::iterator position;
    };

    // shared with awaiters so a racing cancellation never touches a dead queue.
    struct State {
        std::mutex mutex;
        std::deque<T> items;
        std::list<Waiter*> waiters;
        bool closed = false;
    };

public:
    class WaitAwaitable {
    public:
        WaitAwaitable(std::shared_ptr<State> state, Canceller canceller) noexcept
            : state_(std::move(state)), canceller_(std::move(canceller)) { }

        WaitAwaitable(const WaitAwaitable&) = delete;
        WaitAwaitable& operator=(const WaitAwaitable&) = delete;

        bool await_ready() const noexcept { return false; }

        bool await_suspend(std::coroutine_handle<> handle) {
            if (canceller_.isTriggered()) {
                waiter_.canceled = true;
                return false;
            }

            waiter_.completion.prepare(handle);
            {
                std::lock_guard lock(state_->mutex);
                if (!state_->items.empty()) {
                    waiter_.value.emplace(std::move(state_->items.front()));
                    state_->items.pop_front();
                    return false;
                }

                if (state_->closed) {
                    waiter_.closed = true;
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
                            return; // already served by push() / close().
                        }

                        state_->waiters.erase(waiter_.position);
                        waiter_.linked = false;
                    }

                    waiter_.completion.tryComplete([this] { waiter_.canceled = true; });
                });
            }

            return waiter_.completion.finishSuspend();
        }

        T await_resume() {
            registration_.reset();

            if (waiter_.value) {
                return std::move(*waiter_.value);
            }

            if (waiter_.canceled) {
                throw OperationCanceled();
            }

            throw QueueClosed();
        }

    private:
        std::shared_ptr<State> state_;
        Canceller canceller_;
        Waiter waiter_;
        CancelRegistration registration_;
    };

    AsyncQueue() : state_(std::make_shared<State>()) { }
    ~AsyncQueue() { close(); }

    AsyncQueue(const AsyncQueue&) = delete;
    AsyncQueue& operator=(const AsyncQueue&) = delete;

    /** Enqueues an item, handing it directly to the oldest waiter if any. */
    template<typename U = T>
    void push(U&& item) {
        Waiter* waiter = nullptr;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->closed) {
                throw QueueClosed();
            }

            if (state_->waiters.empty()) {
                state_->items.emplace_back(std::forward<U>(item));
                return;
            }

            waiter = state_->waiters.front();
            state_->waiters.pop_front();
            waiter->linked = false;
            waiter->value.emplace(std::forward<U>(item));
        }

        // unlinked under the lock: we exclusively own this completion now.
        waiter->completion.tryComplete();
    }

    std::optional<T> tryPop() {
        std::lock_guard lock(state_->mutex);
        if (state_->items.empty()) {
            return std::nullopt;
        }

        std::optional<T> item(std::move(state_->items.front()));
        state_->items.pop_front();
        return item;
    }

    /** Waits for the next item. */
    WaitAwaitable wait(Canceller canceller = { }) {
        return WaitAwaitable(state_, std::move(canceller));
    }

    /**
     * Rejects further pushes and wakes every waiter with `QueueClosed`.
     * Items already queued can still be taken by `tryPop()` / `wait()`.
     */
    void close() {
        std::list<Waiter*> waiters;
        {
            std::lock_guard lock(state_->mutex);
            state_->closed = true;
            waiters.swap(state_->waiters);
            for (auto* waiter : waiters) {
                waiter->linked = false;
                waiter->closed = true;
            }
        }

        for (auto* waiter : waiters) {
            waiter->completion.tryComplete();
        }
    }

    bool isClosed() const {
        std::lock_guard lock(state_->mutex);
        return state_->closed;
    }

    std::size_t size() const {
        std::lock_guard lock(state_->mutex);
        return state_->items.size();
    }

private:
    std::shared_ptr<State> state_;
};

} // namespace taskpp
