#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Timer.hpp>

#include <mutex>

namespace taskpp {

CancelRegistration Canceller::onTriggered(std::function<void()> callback) const {
    if (!token_.stop_possible()) {
        return CancelRegistration();
    }

    return CancelRegistration(std::make_unique<CancelRegistration::Callback>(token_, std::move(callback)));
}

struct CancellerSource::Shared {
    std::stop_source source;
    std::vector<CancelRegistration> links;

    std::mutex mutex;
    TimerService::Id timer = 0;

    ~Shared() {
        links.clear();      // detach from the parents first.

        if (timer) {
            TimerService::instance().cancel(timer);
        }
    }
};

CancellerSource::CancellerSource()
    : shared_(std::make_shared<Shared>()),
      canceller(shared_->source.get_token())
{
}

CancellerSource::CancellerSource(const Canceller& parent)
    : CancellerSource(std::vector<Canceller> { parent })
{
}

CancellerSource::CancellerSource(const std::vector<Canceller>& parents)
    : CancellerSource()
{
    shared_->links.reserve(parents.size());
    for (const auto& parent : parents) {
        // capture the stop_source by value: it shares (and keeps alive) the state.
        shared_->links.push_back(parent.onTriggered([source = shared_->source]() mutable {
            source.request_stop();
        }));
    }
}

bool CancellerSource::isTriggered() const noexcept {
    return shared_->source.stop_requested();
}

bool CancellerSource::trigger() noexcept {
    return shared_->source.request_stop();
}

void CancellerSource::cancelAfter(TimeSpan delay) {
    if (delay <= TimeSpan::zero()) {
        trigger();
        return;
    }

    auto& timers = TimerService::instance();
    std::weak_ptr<Shared> weak = shared_;

    const auto id = timers.scheduleAfter(delay, [weak] {
        if (auto shared = weak.lock()) {
            shared->source.request_stop();
        }
    });

    TimerService::Id previous;
    {
        std::lock_guard lock(shared_->mutex);
        previous = std::exchange(shared_->timer, id);
    }

    if (previous) {
        timers.cancel(previous);
    }
}

} // namespace taskpp
