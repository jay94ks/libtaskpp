#pragma once
#include <taskpp/Config.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace taskpp {

/** I/O readiness flags. `Error` and `Hangup` are always reported, never requested. */
enum IoEvent : int {
    IoNone = 0,
    IoRead = 1 << 0,
    IoWrite = 1 << 1,
    IoError = 1 << 2,
    IoHangup = 1 << 3,
};

// Short spellings. On Windows <winsock2.h> defines FD_READ / FD_WRITE as macros with
// the same values (1 and 2), so we only define the ones that are not macros already.
#ifndef FD_READ
inline constexpr int FD_READ = IoRead;
#endif
#ifndef FD_WRITE
inline constexpr int FD_WRITE = IoWrite;
#endif
#ifndef FD_ERROR
inline constexpr int FD_ERROR = IoError;
#endif
#ifndef FD_HANGUP
inline constexpr int FD_HANGUP = IoHangup;
#endif

/** Descriptor type: POSIX fd, Windows SOCKET (both fit in intptr_t). */
using IoFd = std::intptr_t;

/** A descriptor and a set of `IoEvent` flags (interest, or readiness). */
struct IoEventInfo {
    IoFd fd;
    int e;  // --> event flags.

    friend bool operator==(const IoEventInfo&, const IoEventInfo&) = default;
};

/**
 * Readiness notification mechanism used by `Monitor` (epoll, poll, WSAPoll, ...).
 *
 * The backend is level-triggered and stateless about waiters: `Monitor` keeps the
 * per-descriptor interest and calls `update()` whenever the union of interests
 * for a descriptor changes. `poll()` is only ever called from the monitor thread;
 * `update()` and `wakeup()` may be called from any thread.
 *
 * On Windows only sockets are supported (a readiness model over `WSAPoll`,
 * see DESIGN.md §5 option 1); regular files/pipes are not pollable.
 */
class MonitorBackend {
public:
    virtual ~MonitorBackend() = default;

    virtual const char* name() const noexcept = 0;

    /** Changes the interest of `fd` from `oldEvents` to `newEvents` (0 = remove). */
    virtual void update(IoFd fd, int oldEvents, int newEvents) = 0;

    /**
     * Blocks until readiness, `wakeup()` or `timeoutMs` (-1 = infinite), and appends
     * ready descriptors to `out`.
     */
    virtual void poll(std::vector<IoEventInfo>& out, int timeoutMs) = 0;

    /** Interrupts a blocking `poll()`. */
    virtual void wakeup() noexcept = 0;

    /** The best backend for this platform (epoll on Linux, poll/WSAPoll elsewhere). */
    static std::unique_ptr<MonitorBackend> createDefault();

#if defined(TASKPP_PLATFORM_LINUX)
    static std::unique_ptr<MonitorBackend> createEpoll();
#endif
#if defined(TASKPP_PLATFORM_POSIX)
    static std::unique_ptr<MonitorBackend> createPoll();
#endif
#if defined(TASKPP_PLATFORM_WINDOWS)
    static std::unique_ptr<MonitorBackend> createWsaPoll();
#endif
};

} // namespace taskpp
