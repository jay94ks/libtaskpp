#include <taskpp/core/Timer.hpp>

namespace taskpp {

TimerService::TimerService()
    : thread_([this] { run(); })
{
}

TimerService::~TimerService() {
    {
        std::lock_guard lock(mutex_);
        stopping_ = true;
    }
    cv_.notify_all();

    if (thread_.joinable()) {
        thread_.join();
    }
}

TimerService& TimerService::instance() {
    // intentionally leaked: timers may be used during static destruction.
    static auto* service = new TimerService();
    return *service;
}

TimerService::Id TimerService::schedule(Clock::time_point due, std::function<void()> callback) {
    bool earliest;
    Id id;
    {
        std::lock_guard lock(mutex_);
        id = ++nextId_;

        auto it = entries_.emplace(std::make_pair(due, id), std::move(callback)).first;
        index_.emplace(id, due);
        earliest = it == entries_.begin();
    }

    if (earliest) {
        cv_.notify_one();
    }

    return id;
}

TimerService::Id TimerService::scheduleAfter(TimeSpan delay, std::function<void()> callback) {
    const auto now = Clock::now();
    const auto limit = Clock::time_point::max() - now;
    const auto span = delay.duration() > limit ? limit : std::chrono::duration_cast<Clock::duration>(delay.duration());
    return schedule(now + span, std::move(callback));
}

bool TimerService::cancel(Id id) {
    std::unique_lock lock(mutex_);
    if (auto it = index_.find(id); it != index_.end()) {
        entries_.erase(std::make_pair(it->second, id));
        index_.erase(it);
        return true;
    }

    if (running_ == id && std::this_thread::get_id() != thread_.get_id()) {
        doneCv_.wait(lock, [&] { return running_ != id; });
    }

    return false;
}

void TimerService::run() {
    std::unique_lock lock(mutex_);

    while (!stopping_) {
        if (entries_.empty()) {
            cv_.wait(lock);
            continue;
        }

        auto it = entries_.begin();
        const auto due = it->first.first;  // copy: the entry may be erased while we wait.
        if (Clock::now() < due) {
            cv_.wait_until(lock, due);
            continue;
        }

        const Id id = it->first.second;
        {
            auto callback = std::move(it->second);
            entries_.erase(it);
            index_.erase(id);
            running_ = id;

            lock.unlock();
            try {
                callback();
            }
            catch (...) {
                // timer callbacks must not throw; swallow to keep the service alive.
            }
            // `callback` (and its captures) is destroyed here, outside the lock.
        }

        lock.lock();
        running_ = 0;
        doneCv_.notify_all();
    }
}

} // namespace taskpp
