#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <atomic>
#include <thread>
#include <vector>

using namespace taskpp;

namespace {

Task<long> consume(Channel<int>* channel, int count) {
    long sum = 0;
    for (int i = 0; i < count; ++i) {
        sum += co_await channel->receive();
    }
    co_return sum;
}

Task<int> receiveOne(Channel<int>* channel, Canceller ct) {
    co_return co_await channel->receive(ct);
}

Task<void> sendOne(Channel<int>* channel, int value, Canceller ct) {
    co_await channel->send(value, ct);
}

Task<void> sendAndFlag(Channel<int>* channel, int value, std::atomic<bool>* flag) {
    co_await channel->send(value);
    flag->store(true);
}

} // namespace

TEST(basic_send_receive) {
    auto w = std::make_shared<ThreadedWorker>();
    Channel<int> ch(4);
    w->sync_wait(sendOne(&ch, 1, { }));
    w->sync_wait(sendOne(&ch, 2, { }));
    CHECK(w->sync_wait(receiveOne(&ch, { })) == 1);
    CHECK(w->sync_wait(receiveOne(&ch, { })) == 2);
}

TEST(backpressure_send_blocks_until_receive) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Channel<int> ch(1);
    w->sync_wait(sendOne(&ch, 1, { })); // fills capacity.

    std::atomic<bool> sent { false };
    w->push(sendAndFlag(&ch, 2, &sent));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(!sent.load()); // blocked: buffer full.

    CHECK(w->sync_wait(receiveOne(&ch, { })) == 1);
    for (int i = 0; i < 100 && !sent.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(sent.load());
    CHECK(w->sync_wait(receiveOne(&ch, { })) == 2);
}

TEST(producer_consumer_across_threads) {
    auto w = std::make_shared<ThreadPooledWorker>(2);
    Channel<int> ch(16);

    std::thread producer([&] {
        for (int i = 1; i <= 5000; ++i) {
            while (!ch.trySend(i)) {
                std::this_thread::yield();
            }
        }
        ch.close();
    });

    long sum = 0;
    try {
        while (true) {
            sum += w->sync_wait(receiveOne(&ch, { }));
        }
    }
    catch (const ChannelClosed&) {
    }
    producer.join();
    CHECK(sum == 5000L * 5001L / 2);
}

TEST(close_drains_then_fails) {
    Channel<int> ch(4);
    CHECK(ch.trySend(1));
    CHECK(ch.trySend(2));
    ch.close();
    CHECK(ch.isClosed());
    CHECK(!ch.trySend(3));

    auto w = std::make_shared<ThreadedWorker>();
    CHECK(w->sync_wait(receiveOne(&ch, { })) == 1);
    CHECK(w->sync_wait(receiveOne(&ch, { })) == 2);
    CHECK_THROWS(ChannelClosed, w->sync_wait(receiveOne(&ch, { })));
    CHECK_THROWS(ChannelClosed, w->sync_wait(sendOne(&ch, 9, { })));
}

TEST(try_send_try_receive) {
    Channel<int> ch(1);
    CHECK(!ch.tryReceive().has_value());
    CHECK(ch.trySend(5));
    CHECK(!ch.trySend(6)); // full.
    auto v = ch.tryReceive();
    CHECK(v && *v == 5);
    CHECK(!ch.tryReceive().has_value());
}

TEST(receive_cancellation) {
    auto w = std::make_shared<ThreadedWorker>();
    Channel<int> ch(1);
    CancellerSource cs;
    cs.cancelAfter(TimeSpan::fromMilliseconds(20));
    CHECK_THROWS(OperationCanceled, w->sync_wait(receiveOne(&ch, cs.canceller)));

    // Canceled receiver must not steal the next item.
    w->sync_wait(sendOne(&ch, 7, { }));
    CHECK(w->sync_wait(receiveOne(&ch, { })) == 7);
}

TEST(send_cancellation_when_full) {
    auto w = std::make_shared<ThreadedWorker>();
    Channel<int> ch(1);
    w->sync_wait(sendOne(&ch, 1, { }));
    CancellerSource cs;
    cs.cancelAfter(TimeSpan::fromMilliseconds(20));
    CHECK_THROWS(OperationCanceled, w->sync_wait(sendOne(&ch, 2, cs.canceller)));
    // Original item is still there.
    CHECK(w->sync_wait(receiveOne(&ch, { })) == 1);
}

TEST(invalid_capacity) {
    CHECK_THROWS(std::invalid_argument, Channel<int>(0));
}

TEST_MAIN()
