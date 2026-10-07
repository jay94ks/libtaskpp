#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <atomic>
#include <chrono>

using namespace taskpp;
using namespace std::chrono_literals;

namespace {

Task<void> pause(TimeSpan span) {
    co_await delay(span);
    co_return;
}

Task<void> pauseChrono(std::chrono::milliseconds span) {
    co_await delay(span); // implicit TimeSpan conversion.
    co_return;
}

Task<void> nap(Canceller ct) {
    co_await delay(TimeSpan::fromSeconds(30), ct);
}

Task<void> countYields(std::atomic<int>* counter, int n) {
    for (int i = 0; i < n; ++i) {
        co_await yield(); // free-function spelling.
        counter->fetch_add(1);
    }
}

Task<bool> yieldStaysOnWorker() {
    auto before = Worker::currentWorker();
    co_await yield();
    co_return before && before == Worker::currentWorker();
}

} // namespace

TEST(delay_timespan) {
    auto w = std::make_shared<ThreadedWorker>();
    const auto start = std::chrono::steady_clock::now();
    w->sync_wait(pause(TimeSpan::fromMilliseconds(30)));
    CHECK(std::chrono::steady_clock::now() - start >= 25ms);
}

TEST(delay_chrono_duration) {
    auto w = std::make_shared<ThreadedWorker>();
    w->sync_wait(pauseChrono(5ms));
    CHECK(true);
}

TEST(delay_zero_completes) {
    auto w = std::make_shared<ThreadedWorker>();
    w->sync_wait(pause(TimeSpan::zero()));
    w->sync_wait(pauseChrono(0ms));
    CHECK(true);
}

TEST(delay_canceled_throws) {
    auto w = std::make_shared<ThreadedWorker>();
    CancellerSource cs;
    cs.trigger();
    CHECK_THROWS(OperationCanceled, w->sync_wait(nap(cs.canceller)));
}

TEST(free_yield_runs) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    std::atomic<int> counter { 0 };
    for (int i = 0; i < 4; ++i) {
        w->push(countYields(&counter, 25));
    }
    w->wait();
    CHECK(counter.load() == 100);
}

TEST(free_yield_stays_on_worker) {
    auto w = std::make_shared<ThreadedWorker>();
    CHECK(w->sync_wait(yieldStaysOnWorker()));
}

TEST_MAIN()
