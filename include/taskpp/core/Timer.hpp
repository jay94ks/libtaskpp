#pragma once
#include <taskpp/TimeSpan.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/detail/Completion.hpp>

#include <chrono>
#include <condition_variable>
#include <coroutine>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>

namespace taskpp {

/**
 * A single-threaded timer queue. Callbacks run on the timer thread, so they must be
 * short; awaitables built on top of it only post a resumption to a worker.
 */
class TimerService {
public:
    using Clock = std::chrono::steady_clock;
    using Id = std::uint64_t;

    TimerService();
    ~TimerService();

    TimerService(const TimerService&) = delete;
    TimerService& operator=(const TimerService&) = delete;

    /** The process wide instance (never destroyed). */
    static TimerService& instance();

    Id schedule(Clock::time_point due, std::function<void()> callback);
    Id scheduleAfter(TimeSpan delay, std::function<void()> callback);

    /**
     * Cancels a pending timer. Returns false if it already fired (or is unknown).
     * If the callback is executing right now on the timer thread, this waits for it
     * to return (unless called from that callback itself), so after `cancel()`
     * returns the callback is guaranteed not to be running.
     */
    bool cancel(Id id);

private:
    void run();

    std::mutex mutex_;
    std::condition_variable cv_;
    std::condition_variable doneCv_;
    std::map<std::pair<Clock::time_point, Id>, std::function<void()>> entries_;
    std::unordered_map<Id, Clock::time_point> index_;
    Id nextId_ = 0;
    Id running_ = 0;
    bool stopping_ = false;
    std::thread thread_;
};

/** Awaitable returned by `delay()`. */
class DelayAwaitable {
public:
    DelayAwaitable(TimeSpan span, Canceller canceller) noexcept
        : span_(span), canceller_(std::move(canceller)) { }

    DelayAwaitable(const DelayAwaitable&) = delete;
    DelayAwaitable& operator=(const DelayAwaitable&) = delete;

    ~DelayAwaitable() {
        // Destroyed while still armed (e.g. the awaiting task was destroyed):
        // drop the timer so its callback never touches this awaitable.
        if (timerId_) {
            TimerService::instance().cancel(timerId_);
        }
    }

    bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> handle) {
        if (canceller_.isTriggered()) {
            canceled_ = true;
            return false;
        }

        if (span_ <= TimeSpan::zero()) {
            return false;
        }

        completion_.prepare(handle);
        timerId_ = TimerService::instance().scheduleAfter(span_, [this] { completion_.tryComplete(); });

        if (canceller_.canBeTriggered()) {
            registration_ = canceller_.onTriggered([this] {
                completion_.tryComplete([this] { canceled_ = true; });
            });
        }

        return completion_.finishSuspend();
    }

    void await_resume() {
        registration_.reset();

        if (timerId_) {
            TimerService::instance().cancel(timerId_);
            timerId_ = 0;
        }

        if (canceled_) {
            throw OperationCanceled();
        }
    }

private:
    TimeSpan span_;
    Canceller canceller_;
    detail::Completion completion_;
    CancelRegistration registration_;
    TimerService::Id timerId_ = 0;
    bool canceled_ = false;
};

/**
 * Suspends the calling coroutine for `span`; it resumes on the same worker.
 * Throws `OperationCanceled` if `canceller` is triggered first.
 */
inline DelayAwaitable delay(TimeSpan span, Canceller canceller = { }) {
    return DelayAwaitable(span, std::move(canceller));
}

} // namespace taskpp
