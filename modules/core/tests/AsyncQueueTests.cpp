#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <atomic>
#include <thread>
#include <vector>

using namespace taskpp;

namespace {

Task<long> consume(AsyncQueue<int>* queue, int count) {
    long sum = 0;
    for (int i = 0; i < count; ++i) {
        sum += co_await queue->wait();
    }
    co_return sum;
}

Task<int> waitOne(AsyncQueue<int>* queue, Canceller ct) {
    co_return co_await queue->wait(ct);
}

Task<void> consumeUntilClosed(AsyncQueue<int>* queue, std::atomic<long>* sum) {
    try {
        while (true) {
            sum->fetch_add(co_await queue->wait());
        }
    }
    catch (const QueueClosed&) {
    }
}

} // namespace

TEST(producer_consumer_across_threads) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    AsyncQueue<int> queue;

    std::thread producer([&] {
        for (int i = 1; i <= 10000; ++i) {
            queue.push(i);
        }
    });

    const long sum = w->sync_wait(consume(&queue, 10000));
    producer.join();
    CHECK(sum == 10000L * 10001L / 2);
}

TEST(many_consumers) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    AsyncQueue<int> queue;
    std::atomic<long> sum { 0 };

    for (int i = 0; i < 8; ++i) {
        w->push(consumeUntilClosed(&queue, &sum));
    }

    for (int i = 1; i <= 1000; ++i) {
        queue.push(i);
    }

    // let consumers drain, then close.
    while (queue.size() > 0) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    queue.close();

    w->wait();
    CHECK(sum.load() == 1000L * 1001L / 2);
}

TEST(wait_cancellation) {
    auto w = std::make_shared<ThreadedWorker>();
    AsyncQueue<int> queue;

    CancellerSource cs;
    cs.cancelAfter(TimeSpan::fromMilliseconds(20));
    CHECK_THROWS(OperationCanceled, w->sync_wait(waitOne(&queue, cs.canceller)));

    // the canceled waiter must not swallow the next item.
    queue.push(5);
    CHECK(w->sync_wait(waitOne(&queue, { })) == 5);
}

TEST(try_pop_and_close) {
    AsyncQueue<int> queue;
    CHECK(!queue.tryPop());
    queue.push(1);
    CHECK(queue.size() == 1);
    CHECK(*queue.tryPop() == 1);

    queue.close();
    CHECK(queue.isClosed());
    CHECK_THROWS(QueueClosed, queue.push(2));

    auto w = std::make_shared<ThreadedWorker>();
    CHECK_THROWS(QueueClosed, w->sync_wait(waitOne(&queue, { })));
}

TEST_MAIN()
