#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <atomic>
#include <chrono>

using namespace taskpp;
using Clock = std::chrono::steady_clock;

namespace {

AsyncQueue<int> gQueue;

Task<void> coroutineNoReturn(Canceller ct, std::atomic<int>* processed) {
    while (ct.isTriggered() == false) {
        try {
            auto item = co_await gQueue.wait(ct);
            processed->fetch_add(item);
        }
        catch (const OperationCanceled&) {
            break;
        }
    }
}

// --> the canceller sample from the specification.
Task<void> sampleForCanceller(std::atomic<int>* processed) {
    CancellerSource cs;

    cs.cancelAfter(TimeSpan::fromMilliseconds(50));
    co_await coroutineNoReturn(cs.canceller, processed);

    if (!cs.isTriggered()) {
        cs.trigger();
    }
}

Task<int> coroutineFunction(Canceller ct) {
    ct.throwIfCanceled();
    co_return 123;
}

Task<void> sleepFor(TimeSpan span, Canceller ct) {
    co_await delay(span, ct);
}

} // namespace

TEST(trigger_and_query) {
    CancellerSource cs;
    CHECK(!cs.isTriggered());
    CHECK(!cs.canceller.isTriggered());
    CHECK(cs.canceller.canBeTriggered());

    CHECK(cs.trigger());
    CHECK(!cs.trigger());
    CHECK(cs.isTriggered());
    CHECK(cs.canceller.isTriggered());
    CHECK_THROWS(OperationCanceled, cs.canceller.throwIfCanceled());

    CHECK(!Canceller::none().canBeTriggered());
    Canceller::none().throwIfCanceled();
}

TEST(throw_if_canceled_in_task) {
    auto w = std::make_shared<ThreadedWorker>();
    CancellerSource cs;
    CHECK(w->sync_wait(coroutineFunction(cs.canceller)) == 123);
    cs.trigger();
    CHECK_THROWS(OperationCanceled, w->sync_wait(coroutineFunction(cs.canceller)));
}

TEST(on_triggered_callbacks) {
    CancellerSource cs;
    int called = 0;
    {
        auto reg = cs.canceller.onTriggered([&] { ++called; });
        auto unregistered = cs.canceller.onTriggered([&] { called += 100; });
        unregistered.reset();
        cs.trigger();
    }
    CHECK(called == 1);

    auto late = cs.canceller.onTriggered([&] { ++called; });
    CHECK(called == 2);   // already triggered: runs immediately.
}

TEST(linked_sources) {
    CancellerSource parent;
    CancellerSource child(parent.canceller);
    CHECK(!child.isTriggered());
    parent.trigger();
    CHECK(child.isTriggered());

    CancellerSource other;
    CancellerSource child2(other.canceller);
    child2.trigger();
    CHECK(!other.isTriggered());   // propagation is one-way.
}

TEST(cancel_after) {
    CancellerSource cs;
    const auto start = Clock::now();
    cs.cancelAfter(TimeSpan::fromMilliseconds(30));

    while (!cs.isTriggered() && Clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    CHECK(cs.isTriggered());
    CHECK(Clock::now() - start >= std::chrono::milliseconds(25));
}

TEST(cancel_after_rearm_and_drop) {
    {
        CancellerSource cs;
        cs.cancelAfter(TimeSpan::fromSeconds(10));
        cs.cancelAfter(TimeSpan::fromMilliseconds(10));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        CHECK(cs.isTriggered());
    }
    {
        // destroying the source discards its timer.
        CancellerSource cs;
        cs.cancelAfter(TimeSpan::fromMilliseconds(5));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
}

TEST(delay_and_cancellation) {
    auto w = std::make_shared<ThreadPooledWorker>(2);

    auto start = Clock::now();
    w->sync_wait(sleepFor(TimeSpan::fromMilliseconds(30), { }));
    CHECK(Clock::now() - start >= std::chrono::milliseconds(25));

    CancellerSource cs;
    cs.cancelAfter(TimeSpan::fromMilliseconds(20));
    start = Clock::now();
    CHECK_THROWS(OperationCanceled, w->sync_wait(sleepFor(TimeSpan::fromSeconds(30), cs.canceller)));
    CHECK(Clock::now() - start < std::chrono::seconds(5));

    // already triggered: throws without waiting.
    CHECK_THROWS(OperationCanceled, w->sync_wait(sleepFor(TimeSpan::fromSeconds(30), cs.canceller)));
}

TEST(spec_sample_for_canceller) {
    std::shared_ptr<Worker> w = std::make_shared<ThreadPooledWorker>(2);
    std::atomic<int> processed { 0 };

    gQueue.push(1);
    gQueue.push(2);

    const auto start = Clock::now();
    w->sync_wait(sampleForCanceller(&processed));
    CHECK(processed.load() == 3);
    CHECK(Clock::now() - start >= std::chrono::milliseconds(40));
}

TEST(many_delays_race_with_cancellation) {
    auto w = std::make_shared<ThreadPooledWorker>(4);
    std::atomic<int> finished { 0 };

    for (int i = 0; i < 500; ++i) {
        w->push([](int i, std::atomic<int>* finished) -> Task<void> {
            CancellerSource cs;
            cs.cancelAfter(TimeSpan::fromMicroseconds(i % 50));
            try {
                co_await delay(TimeSpan::fromMicroseconds(25), cs.canceller);
            }
            catch (const OperationCanceled&) {
            }
            finished->fetch_add(1);
        }(i, &finished));
    }

    w->wait();
    CHECK(finished.load() == 500);
}

TEST_MAIN()
