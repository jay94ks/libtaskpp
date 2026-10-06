#include <taskpp/core/ThreadPooledWorker.hpp>
#include <taskpp/core/ThreadedWorker.hpp>
#include <taskpp/core/Worker.hpp>
#include <taskpp/core/detail/Completion.hpp>

#include "ThreadGroup.hpp"
#include "WorkerInternal.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <stdexcept>

namespace taskpp {
namespace detail {

namespace {
thread_local Worker* tlCurrentWorker = nullptr;
}

Worker* currentWorkerRaw() noexcept { return tlCurrentWorker; }

Worker* exchangeCurrentWorker(Worker* worker) noexcept {
    return std::exchange(tlCurrentWorker, worker);
}

// --------------------------------------------------------------------- TaskTracker

void TaskTracker::add() {
    std::lock_guard lock(mutex_);
    ++count_;
}

void TaskTracker::done() {
    std::lock_guard lock(mutex_);
    if (--count_ == 0) {
        cv_.notify_all();
    }
}

void TaskTracker::wait() {
    std::unique_lock lock(mutex_);
    cv_.wait(lock, [this] { return count_ == 0; });
}

bool TaskTracker::waitFor(TimeSpan timeout) {
    std::unique_lock lock(mutex_);
    return cv_.wait_for(lock, timeout.duration(), [this] { return count_ == 0; });
}

std::size_t TaskTracker::pending() const {
    std::lock_guard lock(mutex_);
    return count_;
}

void TaskTracker::setHandler(ExceptionHandler handler) {
    std::lock_guard lock(mutex_);
    handler_ = std::move(handler);
}

void TaskTracker::report(std::exception_ptr error) noexcept {
    ExceptionHandler handler;
    {
        std::lock_guard lock(mutex_);
        handler = handler_;
    }

    try {
        if (handler) {
            handler(error);
            return;
        }

        std::rethrow_exception(error);
    }
    catch (const std::exception& e) {
        std::fprintf(stderr, "[taskpp] unhandled exception in a pushed task: %s\n", e.what());
    }
    catch (...) {
        std::fprintf(stderr, "[taskpp] unhandled non-standard exception in a pushed task.\n");
    }
}

// --------------------------------------------------------------------- ResumeTarget

ResumeTarget ResumeTarget::capture() noexcept {
    ResumeTarget target;
    if (auto* worker = tlCurrentWorker) {
        target.worker_ = worker->weak_from_this();
    }
    return target;
}

void ResumeTarget::post(std::coroutine_handle<> handle) const noexcept {
    if (auto worker = worker_.lock()) {
        worker->schedule(handle);
        return;
    }

    if (auto fallback = Worker::defaultWorker()) {
        fallback->schedule(handle);
        return;
    }

    // process shutdown: no worker left to run it.
    handle.resume();
}

} // namespace detail

// --------------------------------------------------------------------- Worker

namespace {

std::atomic<bool> gDefaultShutdown { false };

struct DefaultWorkerHolder {
    std::mutex mutex;
    std::shared_ptr<Worker> worker;

    ~DefaultWorkerHolder() {
        std::shared_ptr<Worker> last;
        {
            std::lock_guard lock(mutex);
            gDefaultShutdown.store(true, std::memory_order_release);
            last = std::move(worker);
        }
        // `last` is released here, outside the lock: this drains and joins the pool.
    }
};

DefaultWorkerHolder& defaultHolder() {
    static DefaultWorkerHolder holder;
    return holder;
}

} // namespace

Worker::Worker()
    : tracker_(std::make_shared<detail::TaskTracker>())
{
}

Worker::~Worker() = default;

std::shared_ptr<Worker> Worker::currentWorker() noexcept {
    if (auto* worker = detail::tlCurrentWorker) {
        return worker->weak_from_this().lock();
    }
    return nullptr;
}

std::shared_ptr<Worker> Worker::defaultWorker() {
    if (gDefaultShutdown.load(std::memory_order_acquire)) {
        return nullptr;
    }

    auto& holder = defaultHolder();
    std::lock_guard lock(holder.mutex);
    if (gDefaultShutdown.load(std::memory_order_acquire)) {
        return nullptr;
    }

    if (!holder.worker) {
        holder.worker = std::make_shared<ThreadPooledWorker>();
    }

    return holder.worker;
}

void Worker::setDefaultWorker(std::shared_ptr<Worker> worker) {
    auto& holder = defaultHolder();
    std::shared_ptr<Worker> previous;
    {
        std::lock_guard lock(holder.mutex);
        previous = std::exchange(holder.worker, std::move(worker));
    }
}

bool Worker::isCurrent() const noexcept {
    return detail::tlCurrentWorker == this;
}

void Worker::wait() {
    if (isCurrent()) {
        throw std::logic_error("Worker::wait() called on the worker's own thread would deadlock.");
    }

    tracker_->wait();
}

bool Worker::waitFor(TimeSpan timeout) {
    if (isCurrent()) {
        throw std::logic_error("Worker::waitFor() called on the worker's own thread would deadlock.");
    }

    return tracker_->waitFor(timeout);
}

std::size_t Worker::pendingCount() const {
    return tracker_->pending();
}

void Worker::setUnhandledExceptionHandler(ExceptionHandler handler) {
    tracker_->setHandler(std::move(handler));
}

Worker::ScheduleAwaitable Worker::yield() {
    auto worker = currentWorker();
    if (!worker) {
        worker = defaultWorker();
    }

    if (!worker) {
        throw std::runtime_error("no worker available to yield to.");
    }

    return ScheduleAwaitable(std::move(worker));
}

Worker::ScheduleAwaitable Worker::switchTo(std::shared_ptr<Worker> worker) {
    if (!worker) {
        throw std::invalid_argument("cannot switch to a null worker.");
    }

    return ScheduleAwaitable(std::move(worker));
}

Worker::ExecutionScope::ExecutionScope(Worker* worker) noexcept
    : previous_(detail::exchangeCurrentWorker(worker))
{
}

Worker::ExecutionScope::~ExecutionScope() {
    detail::exchangeCurrentWorker(previous_);
}

// --------------------------------------------------------------------- ThreadedWorker

ThreadedWorker::ThreadedWorker()
    : group_(std::make_unique<detail::ThreadGroup>(this, 1))
{
}

ThreadedWorker::~ThreadedWorker() {
    group_.reset(); // drain + join while the derived object is still intact.
}

void ThreadedWorker::schedule(std::coroutine_handle<> handle) {
    group_->schedule(handle);
}

std::thread::id ThreadedWorker::threadId() const noexcept {
    return group_->threadId(0);
}

// --------------------------------------------------------------------- ThreadPooledWorker

namespace {

std::size_t resolveThreadCount(std::size_t threads) {
    if (threads == 0) {
        threads = std::thread::hardware_concurrency();
    }
    return std::max<std::size_t>(threads, 1);
}

} // namespace

ThreadPooledWorker::ThreadPooledWorker(std::size_t threads)
    : group_(std::make_unique<detail::ThreadGroup>(this, resolveThreadCount(threads)))
{
}

ThreadPooledWorker::~ThreadPooledWorker() {
    group_.reset();
}

void ThreadPooledWorker::schedule(std::coroutine_handle<> handle) {
    group_->schedule(handle);
}

std::size_t ThreadPooledWorker::threadCount() const noexcept {
    return group_->size();
}

} // namespace taskpp
