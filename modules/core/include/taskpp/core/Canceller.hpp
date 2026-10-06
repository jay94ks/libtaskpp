#pragma once
#include <taskpp/Exceptions.hpp>
#include <taskpp/TimeSpan.hpp>

#include <functional>
#include <memory>
#include <stop_token>
#include <vector>

namespace taskpp {

/**
 * RAII handle of a callback registered with `Canceller::onTriggered`.
 * Destroying it unregisters the callback; if the callback is running on another
 * thread at that moment, the destructor waits for it to return.
 */
class CancelRegistration {
public:
    CancelRegistration() noexcept = default;
    CancelRegistration(CancelRegistration&&) noexcept = default;
    CancelRegistration& operator=(CancelRegistration&&) noexcept = default;

    bool isRegistered() const noexcept { return static_cast<bool>(callback_); }
    void reset() noexcept { callback_.reset(); }

private:
    friend class Canceller;
    using Callback = std::stop_callback<std::function<void()>>;

    explicit CancelRegistration(std::unique_ptr<Callback> callback) noexcept
        : callback_(std::move(callback)) { }

    std::unique_ptr<Callback> callback_;
};

/**
 * The observing side of a cancellation signal; cheap to copy, pass by value.
 * A default constructed canceller is never triggered (`Canceller::none()`).
 */
class Canceller {
public:
    Canceller() noexcept = default;
    explicit Canceller(std::stop_token token) noexcept : token_(std::move(token)) { }

    static Canceller none() noexcept { return Canceller(); }

    bool isTriggered() const noexcept { return token_.stop_requested(); }

    /** false when nobody can ever trigger this canceller (e.g. `none()`). */
    bool canBeTriggered() const noexcept { return token_.stop_possible(); }

    void throwIfCanceled() const {
        if (isTriggered()) {
            throw OperationCanceled();
        }
    }

    /**
     * Registers `callback` to run once when triggered (runs immediately, on the
     * calling thread, if already triggered). Otherwise it runs on the thread that
     * calls `CancellerSource::trigger()`; keep it short and non-blocking.
     */
    [[nodiscard]] CancelRegistration onTriggered(std::function<void()> callback) const;

    const std::stop_token& token() const noexcept { return token_; }

private:
    std::stop_token token_;
};

/**
 * The owning side of a cancellation signal.
 *
 * Copies share the same signal. `canceller` is exposed as a member so that the
 * natural spelling `f(cs.canceller)` works.
 */
class CancellerSource {
    struct Shared;

public:
    CancellerSource();

    /** Creates a source that is also triggered when any of `parents` is triggered. */
    explicit CancellerSource(const Canceller& parent);
    explicit CancellerSource(const std::vector<Canceller>& parents);

    CancellerSource(const CancellerSource&) = default;
    CancellerSource(CancellerSource&&) noexcept = default;
    CancellerSource& operator=(const CancellerSource&) = delete;
    CancellerSource& operator=(CancellerSource&&) = delete;
    ~CancellerSource() = default;

    bool isTriggered() const noexcept;

    /** Triggers the signal. Returns false if it was already triggered. */
    bool trigger() noexcept;

    /**
     * Triggers the signal after `delay`. Calling it again re-arms the deadline
     * (the previous one is discarded). The timer is dropped when the last copy of
     * the source is destroyed.
     */
    void cancelAfter(TimeSpan delay);

private:
    std::shared_ptr<Shared> shared_;

public:
    const Canceller canceller;
};

} // namespace taskpp
