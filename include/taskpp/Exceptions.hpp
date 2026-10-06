#pragma once
#include <stdexcept>

namespace taskpp {

/** Thrown when an operation is aborted by a `Canceller` (or by its owner). */
class OperationCanceled : public std::runtime_error {
public:
    OperationCanceled() : std::runtime_error("the operation was canceled.") { }
    using std::runtime_error::runtime_error;
};

/** Thrown when waiting on, or pushing to, a closed `AsyncQueue`. */
class QueueClosed : public std::runtime_error {
public:
    QueueClosed() : std::runtime_error("the queue is closed.") { }
    using std::runtime_error::runtime_error;
};

/** Thrown when sending to, or receiving from, a closed `Channel`. */
class ChannelClosed : public QueueClosed {
public:
    ChannelClosed() : QueueClosed("the channel is closed.") { }
    using QueueClosed::QueueClosed;
};

/** Thrown by `withTimeout` when the deadline expires first. */
class Timeout : public OperationCanceled {
public:
    Timeout() : OperationCanceled("the operation timed out.") { }
    using OperationCanceled::OperationCanceled;
};

/** Thrown when the peer closes a socket before the requested bytes arrive. */
class SocketClosed : public std::runtime_error {
public:
    SocketClosed() : std::runtime_error("the socket was closed by the peer.") { }
    using std::runtime_error::runtime_error;
};

} // namespace taskpp
