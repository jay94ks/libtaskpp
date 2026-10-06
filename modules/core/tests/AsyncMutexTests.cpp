#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <atomic>
#include <thread>
#include <vector>

using namespace taskpp;

namespace {

Task<void> critical(AsyncMutex* mutex, std::atomic<int>* inside, std::atomic<int>* violations, int iterations) {
    for (int i = 0; i < iterations; ++i) {
        auto guard = co_await mutex->lock();
        const int n = inside->fetch_add(1) + 1;
        if (n != 1) {
            violations->fetch_add(1);
        }
        co_await Worker::yield();
        inside->fetch_sub(1);
    }
}

Task<bool> tryLockFailsWhenHeld(AsyncMutex* mutex) {
    auto held = co_await mutex->lock();
    // Same worker: tryLock must fail while held.
    auto second = mutex->tryLock();
    co_return !second.has_value();
}

Task<int> holdsLock(AsyncMutex* mutex, Canceller ct) {
    auto guard = co_await mutex->lock(ct);
    co_await delay(TimeSpan::fromSeconds(30), ct);
    co_return 0;
}

Task<AsyncMutex::ScopedLock> acquire(AsyncMutex* mutex) {
    co_return co_await mutex->lock();
}

Task<void> waitAndRecord(AsyncMutex* mutex, std::vector<int>* order, int id) {
    auto guard = co_await mutex->lock();
    order->push_back(id);
    co_return;
}

} // namespace

TEST(mutual_exclusion_across_workers) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    AsyncMutex mutex;
    std::atomic<int> inside { 0 };
    std::atomic<int> violations { 0 };

    for (int i = 0; i < 8; ++i) {
        w->push(critical(&mutex, &inside, &violations, 50));
    }
    w->wait();
    CHECK(violations.load() == 0);
    CHECK(!mutex.isLocked());
}

TEST(try_lock) {
    auto w = std::make_shared<ThreadedWorker>();
    AsyncMutex mutex;
    {
        auto guard = mutex.tryLock();
        CHECK(guard.has_value());
        CHECK(mutex.isLocked());
        CHECK(!mutex.tryLock().has_value());
    }
    CHECK(!mutex.isLocked());
    CHECK(w->sync_wait(tryLockFailsWhenHeld(&mutex)));
}

TEST(lock_cancellation) {
    auto w = std::make_shared<ThreadedWorker>();
    AsyncMutex mutex;
    auto held = w->sync_wait(acquire(&mutex));

    CancellerSource cs;
    cs.cancelAfter(TimeSpan::fromMilliseconds(20));
    CHECK_THROWS(OperationCanceled, w->sync_wait(holdsLock(&mutex, cs.canceller)));

    // The canceled waiter must not steal the lock.
    held.unlock();
    auto guard = w->sync_wait(acquire(&mutex));
    CHECK(guard.owns());
}

TEST(fifo_order) {
    auto w = std::make_shared<ThreadedWorker>();
    AsyncMutex mutex;
    std::vector<int> order;

    auto holder = w->sync_wait(acquire(&mutex));

    // Queue three waiters while held; they must acquire in order.
    w->push(waitAndRecord(&mutex, &order, 1));
    w->push(waitAndRecord(&mutex, &order, 2));
    w->push(waitAndRecord(&mutex, &order, 3));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    holder.unlock();
    w->wait();
    CHECK(order.size() == 3);
    CHECK(order[0] == 1 && order[1] == 2 && order[2] == 3);
}

TEST_MAIN()
