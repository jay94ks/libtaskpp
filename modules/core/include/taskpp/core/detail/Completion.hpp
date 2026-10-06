#pragma once
#include <atomic>
#include <coroutine>
#include <memory>

namespace taskpp {

class Worker;

namespace detail {

/**
 * Remembers *where* a suspended coroutine should be resumed: the worker that was
 * running it when it suspended. Resumption after an I/O event, a timer, a
 * cancellation or a queue push is posted back to that worker, so a coroutine
 * never silently migrates to the reactor / timer / producer thread.
 *
 * Fallback order: captured worker -> default worker -> inline (only during shutdown).
 */
class ResumeTarget {
public:
    static ResumeTarget capture() noexcept;
    void post(std::coroutine_handle<> handle) const noexcept;

private:
    std::weak_ptr<Worker> worker_;
};

/**
 * One-shot completion latch for awaitables that can be completed from several
 * sources (event, timer, cancellation) and from foreign threads.
 *
 * 1) `prepare()` at the beginning of `await_suspend`.
 * 2) Arm the event sources.
 * 3) `return finishSuspend();` at the end of `await_suspend`.
 *
 * A completer calls `tryComplete()`; exactly one wins. The coroutine is resumed
 * only after *both* the winner completed and `await_suspend` finished arming, so a
 * completer racing with `await_suspend` can never resume (and destroy) the awaiter
 * while it is still being armed. If completion happens during arming,
 * `finishSuspend()` returns false and the coroutine simply continues inline.
 */
class Completion {
public:
    void prepare(std::coroutine_handle<> handle) noexcept {
        handle_ = handle;
        target_ = ResumeTarget::capture();
    }

    bool tryComplete() noexcept {
        return tryComplete([] { });
    }

    /** `onWin` runs only for the winner, before the coroutine can be resumed. */
    template<typename Fn>
    bool tryComplete(Fn&& onWin) noexcept {
        bool expected = false;
        if (!done_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            return false;
        }

        onWin();
        release();
        return true;
    }

    bool isCompleted() const noexcept { return done_.load(std::memory_order_acquire); }

    /** Return value for `await_suspend`: true = stay suspended. */
    bool finishSuspend() noexcept {
        return gate_.fetch_sub(1, std::memory_order_acq_rel) != 1;
    }

private:
    void release() noexcept {
        if (gate_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            target_.post(handle_);
        }
    }

    std::atomic<int> gate_ { 2 };
    std::atomic<bool> done_ { false };
    std::coroutine_handle<> handle_;
    ResumeTarget target_;
};

} // namespace detail
} // namespace taskpp
