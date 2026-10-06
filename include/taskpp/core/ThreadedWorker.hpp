#pragma once
#include <taskpp/core/Worker.hpp>

#include <memory>
#include <thread>

namespace taskpp {
namespace detail { class ThreadGroup; }

/**
 * A worker backed by exactly one dedicated thread: every coroutine scheduled on it
 * runs on that thread, so its tasks never run concurrently with each other.
 */
class ThreadedWorker : public Worker {
public:
    ThreadedWorker();
    ~ThreadedWorker() override;

    void schedule(std::coroutine_handle<> handle) override;

    std::thread::id threadId() const noexcept;

private:
    std::unique_ptr<detail::ThreadGroup> group_;
};

} // namespace taskpp
