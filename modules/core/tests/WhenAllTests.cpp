#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace taskpp;

namespace {

template<typename T>
Task<T> value(T v) { co_return std::move(v); }

Task<int> delayedValue(int v, TimeSpan span) {
    co_await delay(span);
    co_return v;
}

Task<void> noop() { co_return; }

Task<void> delayedVoid(TimeSpan span) {
    co_await delay(span);
    co_return;
}

Task<void> failsVoid() {
    throw std::runtime_error("boom");
    co_return;
}

Task<int> failsInt() {
    throw std::runtime_error("boom");
    co_return 0;
}

} // namespace

TEST(when_all_vector) {
    auto w = std::make_shared<ThreadedWorker>();
    std::vector<Task<int>> tasks;
    tasks.push_back(value(1));
    tasks.push_back(value(2));
    tasks.push_back(value(3));
    auto out = w->sync_wait(whenAll(std::move(tasks)));
    CHECK(out.size() == 3);
    CHECK(out[0] == 1 && out[1] == 2 && out[2] == 3);
}

TEST(when_all_vector_concurrent) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    const auto start = std::chrono::steady_clock::now();
    std::vector<Task<int>> tasks;
    for (int i = 0; i < 4; ++i) {
        tasks.push_back(delayedValue(i, TimeSpan::fromMilliseconds(50)));
    }
    auto out = w->sync_wait(whenAll(std::move(tasks)));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(out.size() == 4);
    // Concurrent: ~50ms, not 200ms.
    CHECK(elapsed < std::chrono::milliseconds(150));
}

TEST(when_all_vector_empty) {
    auto w = std::make_shared<ThreadedWorker>();
    auto out = w->sync_wait(whenAll(std::vector<Task<int>> { }));
    CHECK(out.empty());
}

TEST(when_all_vector_first_error_wins) {
    auto w = std::make_shared<ThreadedWorker>();
    std::vector<Task<int>> tasks;
    tasks.push_back(value(1));
    tasks.push_back(failsInt());
    CHECK_THROWS(std::runtime_error, w->sync_wait(whenAll(std::move(tasks))));
}

TEST(when_all_void) {
    auto w = std::make_shared<ThreadedWorker>();
    std::atomic<int> counter { 0 };
    std::vector<Task<void>> tasks;
    for (int i = 0; i < 5; ++i) {
        tasks.push_back([](std::atomic<int>* c) -> Task<void> {
            co_await delay(TimeSpan::fromMilliseconds(5));
            c->fetch_add(1);
        }(&counter));
    }
    w->sync_wait(whenAll(std::move(tasks)));
    CHECK(counter.load() == 5);
}

TEST(when_all_variadic) {
    auto w = std::make_shared<ThreadedWorker>();
    auto tuple = w->sync_wait(whenAll(value(1), value(2), delayedValue(3, TimeSpan::fromMilliseconds(5))));
    CHECK(std::get<0>(tuple) == 1);
    CHECK(std::get<1>(tuple) == 2);
    CHECK(std::get<2>(tuple) == 3);
}

TEST(when_all_variadic_void_maps_to_monostate) {
    auto w = std::make_shared<ThreadedWorker>();
    auto tuple = w->sync_wait(whenAll(value(7), noop()));
    CHECK(std::get<0>(tuple) == 7);
    (void) std::get<1>(tuple);
}

TEST(when_any_vector_first_wins) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    std::vector<Task<int>> tasks;
    tasks.push_back(delayedValue(1, TimeSpan::fromMilliseconds(100)));
    tasks.push_back(delayedValue(2, TimeSpan::fromMilliseconds(10)));
    auto result = w->sync_wait(whenAny(std::move(tasks)));
    CHECK(result.index == 1);
    CHECK(result.value == 2);
}

TEST(when_any_vector_error) {
    auto w = std::make_shared<ThreadedWorker>();
    std::vector<Task<int>> tasks;
    tasks.push_back(failsInt());
    tasks.push_back(delayedValue(2, TimeSpan::fromMilliseconds(50)));
    CHECK_THROWS(std::runtime_error, w->sync_wait(whenAny(std::move(tasks))));
}

TEST(when_any_void_returns_index) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    std::vector<Task<void>> tasks;
    tasks.push_back(delayedVoid(TimeSpan::fromMilliseconds(100)));
    tasks.push_back(delayedVoid(TimeSpan::fromMilliseconds(5)));
    CHECK(w->sync_wait(whenAny(std::move(tasks))) == 1);
}

TEST(when_any_variadic_returns_variant) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    auto v = w->sync_wait(whenAny(delayedValue(1, TimeSpan::fromMilliseconds(100)), value(std::string("fast"))));
    CHECK(v.index() == 1);
    CHECK(std::get<std::string>(v) == "fast");
}

TEST(when_all_cancellation) {
    auto w = std::make_shared<ThreadedWorker>();
    CancellerSource cs;
    cs.cancelAfter(TimeSpan::fromMilliseconds(10));
    std::vector<Task<int>> tasks;
    tasks.push_back(delayedValue(1, TimeSpan::fromSeconds(30)));
    tasks.push_back(delayedValue(2, TimeSpan::fromSeconds(30)));
    CHECK_THROWS(OperationCanceled, w->sync_wait(whenAll(std::move(tasks), cs.canceller)));
}

TEST(with_timeout_returns_value) {
    auto w = std::make_shared<ThreadedWorker>();
    CHECK(w->sync_wait(withTimeout(value(42), TimeSpan::fromSeconds(5))) == 42);
}

TEST(with_timeout_expires) {
    auto w = std::make_shared<ThreadedWorker>();
    CHECK_THROWS(Timeout, w->sync_wait(withTimeout(delayedValue(1, TimeSpan::fromSeconds(30)), TimeSpan::fromMilliseconds(20))));
    // Timeout derives from OperationCanceled so existing handlers still work.
    CHECK_THROWS(OperationCanceled, w->sync_wait(withTimeout(delayedValue(1, TimeSpan::fromSeconds(30)), TimeSpan::fromMilliseconds(20))));
}

TEST(with_timeout_void) {
    auto w = std::make_shared<ThreadedWorker>();
    w->sync_wait(withTimeout(noop(), TimeSpan::fromSeconds(1)));
    CHECK_THROWS(Timeout, w->sync_wait(withTimeout(delayedVoid(TimeSpan::fromSeconds(30)), TimeSpan::fromMilliseconds(10))));
}

TEST_MAIN()
