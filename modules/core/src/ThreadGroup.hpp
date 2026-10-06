#pragma once
#include <taskpp/core/Worker.hpp>

#include <atomic>
#include <condition_variable>
#include <coroutine>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace taskpp::detail {

/**
 * N threads draining one FIFO run queue on behalf of a worker.
 *
 * The queue state is shared with the threads (not owned by the worker object),
 * so the worker may even be destroyed from one of its own threads: that thread is
 * detached and finishes draining the queue on its own.
 */
class ThreadGroup {
public:
    ThreadGroup(Worker* owner, std::size_t threads);
    ~ThreadGroup();

    void schedule(std::coroutine_handle<> handle);

    std::size_t size() const noexcept { return threads_.size(); }
    std::thread::id threadId(std::size_t index) const noexcept { return threads_[index].get_id(); }

private:
    struct Queue {
        std::mutex mutex;
        std::condition_variable cv;
        std::deque<std::coroutine_handle<>> handles;
        bool stopping = false;
        std::atomic<Worker*> owner { nullptr };
    };

    static void run(std::shared_ptr<Queue> queue);
    void shutdown() noexcept;

    std::shared_ptr<Queue> queue_;
    std::vector<std::thread> threads_;
};

} // namespace taskpp::detail
