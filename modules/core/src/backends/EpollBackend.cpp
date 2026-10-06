#include <taskpp/core/MonitorBackend.hpp>

#include <cerrno>
#include <system_error>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace taskpp {
namespace {

std::system_error lastError(const char* what) {
    return std::system_error(errno, std::generic_category(), what);
}

class EpollBackend final : public MonitorBackend {
public:
    EpollBackend() {
        epoll_ = ::epoll_create1(EPOLL_CLOEXEC);
        if (epoll_ < 0) {
            throw lastError("epoll_create1");
        }

        event_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (event_ < 0) {
            auto error = lastError("eventfd");
            ::close(epoll_);
            throw error;
        }

        epoll_event ev { };
        ev.events = EPOLLIN;
        ev.data.fd = event_;
        if (::epoll_ctl(epoll_, EPOLL_CTL_ADD, event_, &ev) < 0) {
            auto error = lastError("epoll_ctl");
            ::close(event_);
            ::close(epoll_);
            throw error;
        }
    }

    ~EpollBackend() override {
        ::close(event_);
        ::close(epoll_);
    }

    const char* name() const noexcept override { return "epoll"; }

    void update(IoFd fd, int oldEvents, int newEvents) override {
        const int native = static_cast<int>(fd);
        if (newEvents == 0) {
            if (::epoll_ctl(epoll_, EPOLL_CTL_DEL, native, nullptr) < 0 && errno != ENOENT && errno != EBADF) {
                throw lastError("epoll_ctl(DEL)");
            }
            return;
        }

        epoll_event ev { };
        ev.events = toEpoll(newEvents);
        ev.data.fd = native;

        int op = oldEvents ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
        if (::epoll_ctl(epoll_, op, native, &ev) == 0) {
            return;
        }

        // recover from an out of sync registration (e.g. fd number reused).
        if (op == EPOLL_CTL_ADD && errno == EEXIST) {
            op = EPOLL_CTL_MOD;
        }
        else if (op == EPOLL_CTL_MOD && errno == ENOENT) {
            op = EPOLL_CTL_ADD;
        }
        else {
            throw lastError("epoll_ctl");
        }

        if (::epoll_ctl(epoll_, op, native, &ev) < 0) {
            throw lastError("epoll_ctl");
        }
    }

    void poll(std::vector<IoEventInfo>& out, int timeoutMs) override {
        epoll_event events[64];
        const int n = ::epoll_wait(epoll_, events, 64, timeoutMs);
        if (n < 0) {
            if (errno == EINTR) {
                return;
            }
            throw lastError("epoll_wait");
        }

        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == event_) {
                std::uint64_t value;
                while (::read(event_, &value, sizeof(value)) > 0) { }
                continue;
            }

            out.push_back({ events[i].data.fd, fromEpoll(events[i].events) });
        }
    }

    void wakeup() noexcept override {
        const std::uint64_t one = 1;
        [[maybe_unused]] auto r = ::write(event_, &one, sizeof(one));
    }

private:
    static std::uint32_t toEpoll(int events) noexcept {
        std::uint32_t result = 0;
        if (events & IoRead) result |= EPOLLIN | EPOLLPRI | EPOLLRDHUP;
        if (events & IoWrite) result |= EPOLLOUT;
        return result;
    }

    static int fromEpoll(std::uint32_t events) noexcept {
        int result = 0;
        if (events & (EPOLLIN | EPOLLPRI)) result |= IoRead;
        if (events & EPOLLOUT) result |= IoWrite;
        if (events & EPOLLERR) result |= IoError;
        if (events & (EPOLLHUP | EPOLLRDHUP)) result |= IoHangup;
        return result;
    }

    int epoll_ = -1;
    int event_ = -1;
};

} // namespace

std::unique_ptr<MonitorBackend> MonitorBackend::createEpoll() {
    return std::make_unique<EpollBackend>();
}

} // namespace taskpp
