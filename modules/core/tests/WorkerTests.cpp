#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <set>
#include <thread>

using namespace taskpp;

namespace {

Task<void> increment(std::atomic<int>* counter) {
    co_await Worker::yield();
    counter->fetch_add(1);
}

Task<bool> isOn(Worker* expected) {
    co_return Worker::currentWorker().get() == expected;
}

Task<std::thread::id> threadOf() {
    co_return std::this_thread::get_id();
}

Task<void> collectThreads(std::mutex* m, std::set<std::thread::id>* ids) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    std::lock_guard lock(*m);
    ids->insert(std::this_thread::get_id());
    co_return;
}

Task<void> throwing() {
    throw std::runtime_error("unhandled");
    co_return;
}

Task<bool> switchAndCheck(std::shared_ptr<Worker> target) {
    co_await Worker::switchTo(target);
    co_return Worker::currentWorker() == target;
}

Task<bool> syncWaitInside(Worker* self) {
    try {
        self->sync_wait(threadOf());
    }
    catch (const std::logic_error&) {
        co_return true;
    }
    co_return false;
}

Task<int> delayed(int v) {
    co_await delay(TimeSpan::fromMilliseconds(10));
    co_return v;
}

Task<std::pair<bool, bool>> resumesOnSameWorker() {
    auto before = Worker::currentWorker();
    co_await delay(TimeSpan::fromMilliseconds(5));
    auto after = Worker::currentWorker();
    co_return std::make_pair(before != nullptr, before == after);
}

} // namespace

TEST(push_and_wait) {
    std::shared_ptr<Worker> w = std::make_shared<ThreadPooledWorker>(4);
    std::atomic<int> counter { 0 };

    for (int i = 0; i < 1000; ++i) {
        w->push(increment(&counter));
    }

    w->wait();
    CHECK(counter.load() == 1000);
    CHECK(w->pendingCount() == 0);
}

TEST(current_worker) {
    std::shared_ptr<Worker> w = std::make_shared<ThreadedWorker>();
    CHECK(Worker::currentWorker() == nullptr);
    CHECK(w->sync_wait(isOn(w.get())));
}

TEST(threaded_worker_uses_one_thread) {
    auto w = std::make_shared<ThreadedWorker>();
    CHECK(w->sync_wait(threadOf()) == w->threadId());
    CHECK(w->sync_wait(threadOf()) == w->threadId());
}

TEST(thread_pool_uses_many_threads) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    CHECK(w->threadCount() == 4);

    std::mutex m;
    std::set<std::thread::id> ids;
    for (int i = 0; i < 16; ++i) {
        w->push(collectThreads(&m, &ids));
    }

    w->wait();
    CHECK(ids.size() > 1);
}

TEST(default_worker_is_thread_pool) {
    auto w = Worker::defaultWorker();
    CHECK(w != nullptr);
    CHECK(dynamic_cast<ThreadPooledWorker*>(w.get()) != nullptr);
    CHECK(w->sync_wait(isOn(w.get())));
}

TEST(unhandled_exception_handler) {
    auto w = std::make_shared<ThreadedWorker>();
    std::atomic<int> errors { 0 };
    w->setUnhandledExceptionHandler([&](std::exception_ptr) { errors.fetch_add(1); });

    w->push(throwing());
    w->push(throwing());
    w->wait();
    CHECK(errors.load() == 2);
}

TEST(sync_wait_on_own_thread_is_rejected) {
    auto w = std::make_shared<ThreadedWorker>();
    CHECK(w->sync_wait(syncWaitInside(w.get())));
}

TEST(switch_to_other_worker) {
    auto a = std::make_shared<ThreadedWorker>();
    auto b = std::make_shared<ThreadedWorker>();
    CHECK(a->sync_wait(switchAndCheck(b)));
}

TEST(timer_resumes_on_original_worker) {
    auto w = std::make_shared<ThreadedWorker>();
    auto [hadWorker, same] = w->sync_wait(resumesOnSameWorker());
    CHECK(hadWorker);
    CHECK(same);

    auto pool = std::make_shared<ThreadPooledWorker>(2);
    auto [hadWorker2, same2] = pool->sync_wait(resumesOnSameWorker());
    CHECK(hadWorker2);
    CHECK(same2);
}

TEST(wait_for_timeout) {
    auto w = std::make_shared<ThreadedWorker>();
    w->push(delayed(1));
    CHECK(!w->waitFor(TimeSpan::fromMicroseconds(1)) || w->pendingCount() == 0);
    CHECK(w->waitFor(TimeSpan::fromSeconds(5)));
}

TEST(destroy_worker_with_pending_timers) {
    // tasks suspended on a timer outlive their worker and finish on the default worker.
    std::atomic<int> counter { 0 };
    {
        auto w = std::make_shared<ThreadedWorker>();
        for (int i = 0; i < 10; ++i) {
            w->push([](std::atomic<int>* c) -> Task<void> {
                co_await delay(TimeSpan::fromMilliseconds(20));
                c->fetch_add(1);
            }(&counter));
        }
    }

    for (int i = 0; i < 200 && counter.load() < 10; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(counter.load() == 10);
}

TEST_MAIN()
