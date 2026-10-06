#pragma once
#include <taskpp/Exceptions.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/detail/Completion.hpp>

#include <coroutine>
#include <cstddef>
#include <deque>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

namespace taskpp {

/**
 * A bounded multi-producer / multi-consumer channel with back-pressure.
 *
 *     Channel<int> ch(16);                  // capacity 16
 *     co_await ch.send(1, ct);              // suspends when full
 *     int v = co_await ch.receive(ct);      // suspends when empty
 *     ch.close();                           // further sends fail; receivers drain then fail
 *
 * - `send` suspends while the buffer is full; `receive` suspends while empty.
 * - Both take an optional `Canceller` and throw `OperationCanceled`.
 * - `close()` rejects further `send`s and wakes pending waiters with
 *   `ChannelClosed`. Buffered items can still be received; once drained,
 *   `receive` throws `ChannelClosed`.
 * - A waiter resumes on the worker it suspended on.
 * - Unbounded channels: use a very large capacity (or `AsyncQueue`).
 */
template<typename T>
class Channel {
    struct Receiver {
        detail::Completion completion;
        std::optional<T> value;
        bool linked = false;
        typename std::list<Receiver*>::iterator position;
        bool canceled = false;
        bool closed = false;
    };

    struct Sender {
        detail::Completion completion;
        std::optional<T> item;
        bool linked = false;
        typename std::list<Sender*>::iterator position;
        bool canceled = false;
        bool closed = false;
    };

    struct State {
        std::mutex mutex;
        std::deque<T> buffer;
        std::size_t capacity;
        std::list<Receiver*> receivers;
        std::list<Sender*> senders;
        bool closed = false;

        explicit State(std::size_t cap) : capacity(cap) { }
    };

public:
    class SendAwaitable {
    public:
        SendAwaitable(std::shared_ptr<State> state, T item, Canceller canceller)
            : state_(std::move(state)), canceller_(std::move(canceller)) {
            sender_.item.emplace(std::move(item));
        }

        SendAwaitable(const SendAwaitable&) = delete;
        SendAwaitable& operator=(const SendAwaitable&) = delete;
        ~SendAwaitable() {
            if (sender_.linked) {
                std::lock_guard lock(state_->mutex);
                if (sender_.linked) {
                    state_->senders.erase(sender_.position);
                    sender_.linked = false;
                }
            }
        }

        bool await_ready() const noexcept { return false; }

        bool await_suspend(std::coroutine_handle<> handle) {
            if (canceller_.isTriggered()) {
                sender_.canceled = true;
                return false;
            }

            sender_.completion.prepare(handle);
            {
                std::lock_guard lock(state_->mutex);
                if (state_->closed) {
                    sender_.closed = true;
                    return false;
                }
                // Fast path: buffer has room and no receiver is parked
                // (receivers are only parked when the buffer is empty).
                if (state_->buffer.size() < state_->capacity && state_->receivers.empty()) {
                    state_->buffer.emplace_back(std::move(*sender_.item));
                    sender_.item.reset();
                    return false;
                }
                // Hand off directly to the oldest receiver.
                if (!state_->receivers.empty()) {
                    Receiver* r = state_->receivers.front();
                    state_->receivers.pop_front();
                    r->linked = false;
                    r->value.emplace(std::move(*sender_.item));
                    sender_.item.reset();
                    // Sender completes inline; receiver is woken below.
                    sender_.closed = false;
                    pendingReceiver_ = r;
                    return false;
                }
                sender_.position = state_->senders.insert(state_->senders.end(), &sender_);
                sender_.linked = true;
            }

            if (canceller_.canBeTriggered()) {
                registration_ = canceller_.onTriggered([this] {
                    {
                        std::lock_guard lock(state_->mutex);
                        if (!sender_.linked) {
                            return;
                        }
                        state_->senders.erase(sender_.position);
                        sender_.linked = false;
                    }
                    sender_.completion.tryComplete([this] { sender_.canceled = true; });
                });
            }

            return sender_.completion.finishSuspend();
        }

        void await_resume() {
            registration_.reset();
            if (pendingReceiver_) {
                pendingReceiver_->completion.tryComplete();
            }
            if (sender_.closed) {
                throw ChannelClosed();
            }
            if (sender_.canceled) {
                throw OperationCanceled();
            }
        }

    private:
        std::shared_ptr<State> state_;
        Canceller canceller_;
        Sender sender_;
        Receiver* pendingReceiver_ = nullptr;
        CancelRegistration registration_;
    };

    class ReceiveAwaitable {
    public:
        ReceiveAwaitable(std::shared_ptr<State> state, Canceller canceller) noexcept
            : state_(std::move(state)), canceller_(std::move(canceller)) { }

        ReceiveAwaitable(const ReceiveAwaitable&) = delete;
        ReceiveAwaitable& operator=(const ReceiveAwaitable&) = delete;
        ~ReceiveAwaitable() {
            if (receiver_.linked) {
                std::lock_guard lock(state_->mutex);
                if (receiver_.linked) {
                    state_->receivers.erase(receiver_.position);
                    receiver_.linked = false;
                }
            }
        }

        bool await_ready() const noexcept { return false; }

        bool await_suspend(std::coroutine_handle<> handle) {
            if (canceller_.isTriggered()) {
                receiver_.canceled = true;
                return false;
            }

            receiver_.completion.prepare(handle);
            {
                std::lock_guard lock(state_->mutex);
                if (!state_->buffer.empty()) {
                    receiver_.value.emplace(std::move(state_->buffer.front()));
                    state_->buffer.pop_front();
                    // Refill from the oldest parked sender (back-pressure release).
                    if (!state_->senders.empty()) {
                        Sender* s = state_->senders.front();
                        state_->senders.pop_front();
                        s->linked = false;
                        state_->buffer.emplace_back(std::move(*s->item));
                        s->item.reset();
                        pendingSender_ = s;
                    }
                    return false;
                }
                if (state_->closed) {
                    receiver_.closed = true;
                    return false;
                }
                receiver_.position = state_->receivers.insert(state_->receivers.end(), &receiver_);
                receiver_.linked = true;
            }

            if (canceller_.canBeTriggered()) {
                registration_ = canceller_.onTriggered([this] {
                    {
                        std::lock_guard lock(state_->mutex);
                        if (!receiver_.linked) {
                            return;
                        }
                        state_->receivers.erase(receiver_.position);
                        receiver_.linked = false;
                    }
                    receiver_.completion.tryComplete([this] { receiver_.canceled = true; });
                });
            }

            return receiver_.completion.finishSuspend();
        }

        T await_resume() {
            registration_.reset();
            if (pendingSender_) {
                pendingSender_->completion.tryComplete();
            }
            if (receiver_.value) {
                return std::move(*receiver_.value);
            }
            if (receiver_.canceled) {
                throw OperationCanceled();
            }
            throw ChannelClosed();
        }

        // Set by await_suspend when it refills the buffer inline.
        Sender* pendingSender_ = nullptr;

    private:
        std::shared_ptr<State> state_;
        Canceller canceller_;
        Receiver receiver_;
        CancelRegistration registration_;
    };

    explicit Channel(std::size_t capacity = 1)
        : state_(std::make_shared<State>(capacity == 0 ? 1 : capacity)) {
        if (capacity == 0) {
            throw std::invalid_argument("channel capacity must be at least 1.");
        }
    }

    ~Channel() { close(); }

    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;

    std::size_t capacity() const noexcept { return state_->capacity; }

    std::size_t size() const {
        std::lock_guard lock(state_->mutex);
        return state_->buffer.size();
    }

    bool isClosed() const {
        std::lock_guard lock(state_->mutex);
        return state_->closed;
    }

    SendAwaitable send(T item, Canceller canceller = { }) {
        return SendAwaitable(state_, std::move(item), std::move(canceller));
    }

    ReceiveAwaitable receive(Canceller canceller = { }) {
        return ReceiveAwaitable(state_, std::move(canceller));
    }

    /** Non-blocking send: false when full or closed. */
    bool trySend(T item) {
        Receiver* receiver = nullptr;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->closed) {
                return false;
            }
            if (!state_->receivers.empty()) {
                receiver = state_->receivers.front();
                state_->receivers.pop_front();
                receiver->linked = false;
                receiver->value.emplace(std::move(item));
            }
            else {
                if (state_->buffer.size() >= state_->capacity) {
                    return false;
                }
                state_->buffer.emplace_back(std::move(item));
                return true;
            }
        }
        receiver->completion.tryComplete();
        return true;
    }

    /** Non-blocking receive. */
    std::optional<T> tryReceive() {
        Sender* sender = nullptr;
        std::optional<T> out;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->buffer.empty()) {
                return std::nullopt;
            }
            out.emplace(std::move(state_->buffer.front()));
            state_->buffer.pop_front();
            if (!state_->senders.empty()) {
                Sender* s = state_->senders.front();
                state_->senders.pop_front();
                s->linked = false;
                state_->buffer.emplace_back(std::move(*s->item));
                s->item.reset();
                sender = s;
            }
        }
        if (sender) {
            sender->completion.tryComplete();
        }
        return out;
    }

    /**
     * Rejects further sends and wakes parked senders with `ChannelClosed`.
     * Parked receivers are woken with `ChannelClosed` as well; buffered items
     * can still be received until drained.
     */
    void close() {
        std::list<Receiver*> receivers;
        std::list<Sender*> senders;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->closed) {
                // Still wake anyone parked after a previous close race.
            }
            state_->closed = true;
            // Only fail receivers when nothing is left to drain.
            if (state_->buffer.empty()) {
                receivers.swap(state_->receivers);
                for (auto* r : receivers) {
                    r->linked = false;
                    r->closed = true;
                }
            }
            senders.swap(state_->senders);
            for (auto* s : senders) {
                s->linked = false;
                s->closed = true;
            }
        }
        for (auto* s : senders) {
            s->completion.tryComplete();
        }
        for (auto* r : receivers) {
            r->completion.tryComplete();
        }
    }

private:
    std::shared_ptr<State> state_;
};

} // namespace taskpp
