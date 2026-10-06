#include <taskpp/core/Monitor.hpp>

#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>

namespace taskpp {

// --------------------------------------------------------------------- Impl

struct Monitor::Impl {
    struct Registration {
        detail::IoWaiter* waiter;
        int events;
    };

    struct FdEntry {
        std::vector<Registration> registrations;
        int armed = 0;  // interest currently set on the backend.
    };

    explicit Impl(std::unique_ptr<MonitorBackend> backend_)
        : backend(std::move(backend_))
    {
        if (!backend) {
            throw std::invalid_argument("a monitor requires a backend.");
        }
    }

    std::unique_ptr<MonitorBackend> backend;
    std::mutex mutex;
    std::unordered_map<int, FdEntry> fds;
    bool stopping = false;
    std::thread thread;

    static int interestOf(const FdEntry& entry) noexcept {
        int events = 0;
        for (const auto& registration : entry.registrations) {
            events |= registration.events;
        }
        return events;
    }

    /** Syncs the backend with the entry's interest; may throw (e.g. EBADF / EPERM). */
    void rearmLocked(int fd, FdEntry& entry) {
        const int wanted = interestOf(entry);
        if (wanted != entry.armed) {
            backend->update(fd, entry.armed, wanted);
            entry.armed = wanted;
        }
    }

    /** Removes every registration of `waiter`. Never throws. */
    void detachLocked(detail::IoWaiter* waiter) noexcept {
        for (const auto& interest : waiter->interests) {
            auto it = fds.find(interest.fd);
            if (it == fds.end()) {
                continue;
            }

            auto& registrations = it->second.registrations;
            std::erase_if(registrations, [&](const Registration& r) { return r.waiter == waiter; });

            try {
                rearmLocked(interest.fd, it->second);
            }
            catch (...) {
                // removal failures (e.g. the fd was already closed) are harmless.
                it->second.armed = interestOf(it->second);
            }

            if (registrations.empty()) {
                fds.erase(it);
            }
        }

        waiter->registered = false;
    }

    void run() {
        std::vector<IoEventInfo> ready;
        std::vector<detail::IoWaiter*> touched;

        while (true) {
            ready.clear();
            touched.clear();

            try {
                backend->poll(ready, -1);
            }
            catch (...) {
                // a broken backend must not kill the reactor; avoid spinning hard.
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            {
                std::lock_guard lock(mutex);
                if (stopping) {
                    break;
                }

                for (const auto& r : ready) {
                    auto it = fds.find(r.fd);
                    if (it == fds.end()) {
                        continue;
                    }

                    for (const auto& registration : it->second.registrations) {
                        const int matched = r.e & (registration.events | IoError | IoHangup);
                        if (!matched) {
                            continue;
                        }

                        auto* waiter = registration.waiter;
                        if (waiter->results.empty()) {
                            touched.push_back(waiter);
                        }

                        auto found = std::find_if(waiter->results.begin(), waiter->results.end(),
                            [&](const IoEventInfo& info) { return info.fd == r.fd; });

                        if (found != waiter->results.end()) {
                            found->e |= matched;
                        }
                        else {
                            waiter->results.push_back({ r.fd, matched });
                        }
                    }
                }

                for (auto* waiter : touched) {
                    detachLocked(waiter);
                }
            }

            // detached under the lock: nobody else can complete these waiters now,
            // so it is safe to complete them without holding the lock.
            for (auto* waiter : touched) {
                waiter->completion.tryComplete();
            }
        }
    }

    void abortAll(std::vector<detail::IoWaiter*>& victims) noexcept {
        for (auto* waiter : victims) {
            waiter->completion.tryComplete([waiter] { waiter->aborted = true; });
        }
    }
};

// --------------------------------------------------------------------- Monitor

Monitor::Monitor(std::unique_ptr<MonitorBackend> backend)
    : impl_(std::make_unique<Impl>(std::move(backend)))
{
    impl_->thread = std::thread([impl = impl_.get()] { impl->run(); });
}

Monitor::~Monitor() {
    {
        std::lock_guard lock(impl_->mutex);
        impl_->stopping = true;
    }

    impl_->backend->wakeup();
    if (impl_->thread.joinable()) {
        impl_->thread.join();
    }

    std::vector<detail::IoWaiter*> victims;
    {
        std::lock_guard lock(impl_->mutex);
        for (auto& [fd, entry] : impl_->fds) {
            for (auto& registration : entry.registrations) {
                if (std::find(victims.begin(), victims.end(), registration.waiter) == victims.end()) {
                    victims.push_back(registration.waiter);
                }
            }
        }

        for (auto* waiter : victims) {
            impl_->detachLocked(waiter);
        }
    }

    impl_->abortAll(victims);
}

Monitor& Monitor::defaultMonitor() {
    // intentionally leaked: waits may be pending during static destruction.
    static auto* monitor = new Monitor();
    return *monitor;
}

IoWaitAwaitable Monitor::wait(int fd, int events, Canceller canceller) {
    return defaultMonitor().watch(fd, events, std::move(canceller));
}

IoWhenAnyAwaitable Monitor::whenAny(std::span<const int> fds, int events, Canceller canceller) {
    return defaultMonitor().watchAny(fds, events, std::move(canceller));
}

IoWhenAnyAwaitable Monitor::whenAny(std::initializer_list<int> fds, int events, Canceller canceller) {
    return defaultMonitor().watchAny(std::span<const int>(fds.begin(), fds.size()), events, std::move(canceller));
}

IoWhenAnyAwaitable Monitor::whenAny(std::vector<IoEventInfo> interests, Canceller canceller) {
    return defaultMonitor().watchAny(std::move(interests), std::move(canceller));
}

IoWaitAwaitable Monitor::watch(int fd, int events, Canceller canceller) {
    return IoWaitAwaitable(*this, { IoEventInfo { fd, events } }, std::move(canceller));
}

IoWhenAnyAwaitable Monitor::watchAny(std::span<const int> fds, int events, Canceller canceller) {
    std::vector<IoEventInfo> interests;
    interests.reserve(fds.size());
    for (int fd : fds) {
        interests.push_back({ fd, events });
    }

    return IoWhenAnyAwaitable(*this, std::move(interests), std::move(canceller));
}

IoWhenAnyAwaitable Monitor::watchAny(std::vector<IoEventInfo> interests, Canceller canceller) {
    return IoWhenAnyAwaitable(*this, std::move(interests), std::move(canceller));
}

void Monitor::cancel(int fd) {
    std::vector<detail::IoWaiter*> victims;
    {
        std::lock_guard lock(impl_->mutex);
        auto it = impl_->fds.find(fd);
        if (it == impl_->fds.end()) {
            return;
        }

        for (auto& registration : it->second.registrations) {
            victims.push_back(registration.waiter);
        }

        for (auto* waiter : victims) {
            impl_->detachLocked(waiter);
        }
    }

    impl_->abortAll(victims);
}

const char* Monitor::backendName() const noexcept {
    return impl_->backend->name();
}

void Monitor::attach(detail::IoWaiter* waiter) {
    std::lock_guard lock(impl_->mutex);
    if (impl_->stopping) {
        throw std::runtime_error("the monitor is shutting down.");
    }

    for (const auto& interest : waiter->interests) {
        impl_->fds[interest.fd].registrations.push_back({ waiter, interest.e });
    }

    try {
        for (const auto& interest : waiter->interests) {
            impl_->rearmLocked(interest.fd, impl_->fds[interest.fd]);
        }
    }
    catch (...) {
        impl_->detachLocked(waiter);
        throw;
    }

    waiter->registered = true;
}

void Monitor::abort(detail::IoWaiter* waiter) {
    {
        std::lock_guard lock(impl_->mutex);
        if (!waiter->registered) {
            return; // already completed (or being completed) by the reactor.
        }

        impl_->detachLocked(waiter);
    }

    waiter->completion.tryComplete([waiter] { waiter->aborted = true; });
}

// --------------------------------------------------------------------- awaitables

namespace detail {

IoAwaitableBase::IoAwaitableBase(Monitor& monitor, std::vector<IoEventInfo> interests, Canceller canceller)
    : monitor_(&monitor), canceller_(std::move(canceller))
{
    if (interests.empty()) {
        throw std::invalid_argument("at least one descriptor is required.");
    }

    for (const auto& interest : interests) {
        if (interest.fd < 0) {
            throw std::invalid_argument("invalid file descriptor.");
        }

        const int events = interest.e & (IoRead | IoWrite);
        if (!events) {
            throw std::invalid_argument("events must contain FD_READ and/or FD_WRITE.");
        }

        // merge duplicated descriptors into one interest.
        auto found = std::find_if(waiter_.interests.begin(), waiter_.interests.end(),
            [&](const IoEventInfo& info) { return info.fd == interest.fd; });

        if (found != waiter_.interests.end()) {
            found->e |= events;
        }
        else {
            waiter_.interests.push_back({ interest.fd, events });
        }
    }
}

bool IoAwaitableBase::await_suspend(std::coroutine_handle<> handle) {
    if (canceller_.isTriggered()) {
        waiter_.aborted = true;
        return false;
    }

    waiter_.completion.prepare(handle);
    monitor_->attach(&waiter_);

    if (canceller_.canBeTriggered()) {
        registration_ = canceller_.onTriggered([this] { monitor_->abort(&waiter_); });
    }

    return waiter_.completion.finishSuspend();
}

std::vector<IoEventInfo>& IoAwaitableBase::finish() {
    registration_.reset();  // waits for an in-flight cancellation callback.

    if (waiter_.aborted) {
        throw OperationCanceled();
    }

    return waiter_.results;
}

} // namespace detail

int IoWaitAwaitable::await_resume() {
    int events = 0;
    for (const auto& info : finish()) {
        events |= info.e;
    }
    return events;
}

std::vector<IoEventInfo> IoWhenAnyAwaitable::await_resume() {
    return std::move(finish());
}

} // namespace taskpp
