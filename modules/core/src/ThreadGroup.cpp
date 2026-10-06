#include "ThreadGroup.hpp"
#include "WorkerInternal.hpp"

namespace taskpp::detail {

ThreadGroup::ThreadGroup(Worker* owner, std::size_t threads)
    : queue_(std::make_shared<Queue>())
{
    queue_->owner.store(owner, std::memory_order_release);
    threads_.reserve(threads);

    try {
        for (std::size_t i = 0; i < threads; ++i) {
            threads_.emplace_back(&ThreadGroup::run, queue_);
        }
    }
    catch (...) {
        shutdown();
        throw;
    }
}

ThreadGroup::~ThreadGroup() {
    shutdown();
}

void ThreadGroup::shutdown() noexcept {
    Worker* owner = queue_->owner.exchange(nullptr, std::memory_order_acq_rel);
    {
        std::lock_guard lock(queue_->mutex);
        queue_->stopping = true;
    }
    queue_->cv.notify_all();

    const auto self = std::this_thread::get_id();
    for (auto& thread : threads_) {
        if (!thread.joinable()) {
            continue;
        }

        if (thread.get_id() == self) {
            // destroyed from inside one of our own tasks: we can't join ourselves.
            // the thread keeps the queue alive and drains it before exiting.
            if (owner && currentWorkerRaw() == owner) {
                exchangeCurrentWorker(nullptr);
            }

            thread.detach();
        }
        else {
            thread.join();
        }
    }

    threads_.clear();
}

void ThreadGroup::schedule(std::coroutine_handle<> handle) {
    {
        std::lock_guard lock(queue_->mutex);
        queue_->handles.push_back(handle);
    }
    queue_->cv.notify_one();
}

void ThreadGroup::run(std::shared_ptr<Queue> queue) {
    while (true) {
        std::coroutine_handle<> handle;
        {
            std::unique_lock lock(queue->mutex);
            queue->cv.wait(lock, [&] { return queue->stopping || !queue->handles.empty(); });

            if (queue->handles.empty()) {
                break; // stopping and drained.
            }

            handle = queue->handles.front();
            queue->handles.pop_front();
        }

        Worker::ExecutionScope scope(queue->owner.load(std::memory_order_acquire));
        handle.resume();
    }
}

} // namespace taskpp::detail
