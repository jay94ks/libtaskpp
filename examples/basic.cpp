// Tasks, cancellation and workers: the usage patterns from the README.

#include <taskpp/taskpp.hpp>

#include <cstdio>

using namespace taskpp;

static AsyncQueue<int> queue;

Task<int> coroutineFunction(Canceller ct) {
    ct.throwIfCanceled();

    co_await delay(TimeSpan::fromMilliseconds(10), ct);

    co_return 123;
}

Task<void> coroutineNoReturn(Canceller ct) {
    while (ct.isTriggered() == false) {
        try {
            // --> pass the canceller, otherwise the wait can't be interrupted.
            auto item = co_await queue.wait(ct);
            std::printf("item: %d\n", item);
        }
        catch (const OperationCanceled&) {
            break;
        }
    }
}

Task<void> sampleForCanceller() {
    CancellerSource cs;

    cs.cancelAfter(TimeSpan::fromMilliseconds(200));
    co_await coroutineNoReturn(cs.canceller);

    if (!cs.isTriggered()) {
        cs.trigger();
    }
}

int main() {
    std::shared_ptr<Worker> w = std::make_shared<ThreadedWorker>();

    // --> invoke the task in the worker and wait for its result.
    std::printf("result: %d\n", w->sync_wait(coroutineFunction(Canceller::none())));

    // --> put tasks, and no-wait.
    queue.push(1);
    queue.push(2);
    w->push(sampleForCanceller());
    queue.push(3);

    // --> wait for completion of all pushed coroutines.
    w->wait();

    // --> the default worker is a ThreadPooledWorker.
    auto pool = Worker::defaultWorker();
    pool->sync_wait([]() -> Task<void> {
        std::printf("running on the default worker: %s\n",
            Worker::currentWorker() == Worker::defaultWorker() ? "yes" : "no");
        co_return;
    }());

    return 0;
}
