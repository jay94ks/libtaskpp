#pragma once
#include <taskpp/core/Worker.hpp>

#include <cstddef>
#include <memory>

namespace taskpp {
namespace detail { class ThreadGroup; }

/**
 * A worker backed by a fixed pool of threads sharing one run queue.
 * This is the type of `Worker::defaultWorker()`.
 */
class ThreadPooledWorker : public Worker {
public:
    /** `threads == 0` means `std::thread::hardware_concurrency()` (at least 1). */
    explicit ThreadPooledWorker(std::size_t threads = 0);
    ~ThreadPooledWorker() override;

    void schedule(std::coroutine_handle<> handle) override;

    std::size_t threadCount() const noexcept;

private:
    std::unique_ptr<detail::ThreadGroup> group_;
};

} // namespace taskpp
