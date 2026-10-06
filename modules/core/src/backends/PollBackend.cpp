#include <taskpp/core/MonitorBackend.hpp>

#include <cerrno>
#include <mutex>
#include <system_error>
#include <unordered_map>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

namespace taskpp {
namespace {

std::system_error lastError(const char* what) {
    return std::system_error(errno, std::generic_category(), what);
}

/** Portable POSIX fallback: rebuilds the pollfd set whenever interest changes. */
class PollBackend final : public MonitorBackend {
public:
    PollBackend() {
        if (::pipe(pipe_) < 0) {
            throw lastError("pipe");
        }

        for (int fd : pipe_) {
            ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
            ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
    }

    ~PollBackend() override {
        ::close(pipe_[0]);
        ::close(pipe_[1]);
    }

    const char* name() const noexcept override { return "poll"; }

    void update(int fd, int /*oldEvents*/, int newEvents) override {
        {
            std::lock_guard lock(mutex_);
            if (newEvents) {
                interest_[fd] = newEvents;
            }
            else {
                interest_.erase(fd);
            }
        }

        wakeup(); // make poll() pick up the new set.
    }

    void poll(std::vector<IoEventInfo>& out, int timeoutMs) override {
        pollfds_.clear();
        pollfds_.push_back({ pipe_[0], POLLIN, 0 });
        {
            std::lock_guard lock(mutex_);
            for (const auto& [fd, events] : interest_) {
                short flags = 0;
                if (events & IoRead) flags |= POLLIN | POLLPRI;
                if (events & IoWrite) flags |= POLLOUT;
                pollfds_.push_back({ fd, flags, 0 });
            }
        }

        const int n = ::poll(pollfds_.data(), static_cast<nfds_t>(pollfds_.size()), timeoutMs);
        if (n < 0) {
            if (errno == EINTR) {
                return;
            }
            throw lastError("poll");
        }

        if (pollfds_[0].revents) {
            char buffer[64];
            while (::read(pipe_[0], buffer, sizeof(buffer)) > 0) { }
        }

        for (std::size_t i = 1; i < pollfds_.size(); ++i) {
            const short revents = pollfds_[i].revents;
            if (!revents) {
                continue;
            }

            int events = 0;
            if (revents & (POLLIN | POLLPRI)) events |= IoRead;
            if (revents & POLLOUT) events |= IoWrite;
            if (revents & (POLLERR | POLLNVAL)) events |= IoError;
            if (revents & POLLHUP) events |= IoHangup;
            out.push_back({ pollfds_[i].fd, events });
        }
    }

    void wakeup() noexcept override {
        const char one = 1;
        [[maybe_unused]] auto r = ::write(pipe_[1], &one, 1);
    }

private:
    int pipe_[2] { -1, -1 };
    std::mutex mutex_;
    std::unordered_map<int, int> interest_;
    std::vector<pollfd> pollfds_;   // only touched by the monitor thread.
};

} // namespace

std::unique_ptr<MonitorBackend> MonitorBackend::createPoll() {
    return std::make_unique<PollBackend>();
}

std::unique_ptr<MonitorBackend> MonitorBackend::createDefault() {
#if defined(TASKPP_PLATFORM_LINUX)
    return createEpoll();
#else
    return createPoll();
#endif
}

} // namespace taskpp
