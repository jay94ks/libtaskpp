#include "TestHarness.hpp"

#include <taskpp/core/Core.hpp>

#include <atomic>
#include <chrono>
#include <thread>

#include <fcntl.h>
#include <unistd.h>

using namespace taskpp;

namespace {

struct Pipe {
    int r = -1, w = -1;

    Pipe() {
        int fds[2];
        if (::pipe(fds) != 0) {
            throw std::runtime_error("pipe");
        }
        r = fds[0];
        w = fds[1];
        ::fcntl(r, F_SETFL, O_NONBLOCK);
        ::fcntl(w, F_SETFL, O_NONBLOCK);
    }

    ~Pipe() {
        if (r >= 0) ::close(r);
        if (w >= 0) ::close(w);
    }

    void write(char c = 'x') const { [[maybe_unused]] auto n = ::write(w, &c, 1); }
};

Task<int> waitReadable(Monitor* monitor, int fd, Canceller ct) {
    int e = co_await monitor->watch(fd, FD_READ, ct);
    co_return e;
}

Task<std::vector<IoEventInfo>> waitAny(Monitor* monitor, std::vector<int> fds) {
    co_return co_await monitor->watchAny(fds, FD_READ);
}

Task<long> echoLoop(Monitor* monitor, int fd, int expected) {
    long received = 0;
    while (received < expected) {
        co_await monitor->watch(fd, FD_READ);
        char buffer[256];
        auto n = ::read(fd, buffer, sizeof(buffer));
        if (n > 0) {
            received += n;
        }
    }
    co_return received;
}

Task<bool> resumesOnSameWorker(Monitor* monitor, int fd) {
    auto before = Worker::currentWorker();
    co_await monitor->watch(fd, FD_READ);
    co_return before && before == Worker::currentWorker();
}

std::unique_ptr<MonitorBackend> makeBackend(const std::string& name) {
#if defined(TASKPP_PLATFORM_LINUX)
    if (name == "epoll") {
        return MonitorBackend::createEpoll();
    }
#endif
    return MonitorBackend::createPoll();
}

void forEachBackend(const std::function<void(Monitor&)>& body) {
    for (const char* name : { "epoll", "poll" }) {
        Monitor monitor(makeBackend(name));
        body(monitor);
    }
}

} // namespace

TEST(wait_single_fd) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadPooledWorker>(2);
        Pipe p;

        std::thread writer([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            p.write();
        });

        const int e = w->sync_wait(waitReadable(&monitor, p.r, { }));
        writer.join();
        CHECK(e & FD_READ);
    });
}

TEST(already_ready_fd) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe p;
        p.write();
        CHECK(w->sync_wait(waitReadable(&monitor, p.r, { })) & FD_READ);
    });
}

TEST(when_any) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe a, b, c;
        b.write();
        c.write();

        auto ready = w->sync_wait(waitAny(&monitor, { a.r, b.r, c.r }));
        CHECK(!ready.empty());
        for (auto& info : ready) {
            CHECK(info.fd == b.r || info.fd == c.r);
            CHECK(info.e & FD_READ);
        }
    });
}

TEST(hangup_is_reported) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe p;
        ::close(p.w);
        p.w = -1;
        CHECK(w->sync_wait(waitReadable(&monitor, p.r, { })) & FD_HANGUP);
    });
}

TEST(wait_cancellation) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe p;

        CancellerSource cs;
        cs.cancelAfter(TimeSpan::fromMilliseconds(20));
        CHECK_THROWS(OperationCanceled, w->sync_wait(waitReadable(&monitor, p.r, cs.canceller)));

        // the fd is usable again afterwards.
        p.write();
        CHECK(w->sync_wait(waitReadable(&monitor, p.r, { })) & FD_READ);
    });
}

TEST(cancel_fd) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadedWorker>();
        Pipe p;

        std::thread canceller([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            monitor.cancel(p.r);
        });

        CHECK_THROWS(OperationCanceled, w->sync_wait(waitReadable(&monitor, p.r, { })));
        canceller.join();
    });
}

TEST(streaming_and_affinity) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadPooledWorker>(3);
        Pipe p;

        std::thread writer([&] {
            for (int i = 0; i < 2000; ++i) {
                p.write();
                if (i % 100 == 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        });

        CHECK(w->sync_wait(echoLoop(&monitor, p.r, 2000)) == 2000);
        writer.join();

        Pipe q;
        q.write();
        CHECK(w->sync_wait(resumesOnSameWorker(&monitor, q.r)));
    });
}

TEST(many_concurrent_waiters_on_one_fd) {
    forEachBackend([](Monitor& monitor) {
        auto w = std::make_shared<ThreadPooledWorker>(4);
        Pipe p;
        std::atomic<int> woke { 0 };

        for (int i = 0; i < 50; ++i) {
            w->push([](Monitor* m, int fd, std::atomic<int>* woke) -> Task<void> {
                co_await m->watch(fd, FD_READ);
                woke->fetch_add(1);
            }(&monitor, p.r, &woke));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        p.write();
        w->wait();
        CHECK(woke.load() == 50);
    });
}

TEST(invalid_arguments) {
    CHECK_THROWS(std::invalid_argument, Monitor::wait(-1, FD_READ));
    CHECK_THROWS(std::invalid_argument, Monitor::wait(0, 0));
    CHECK_THROWS(std::invalid_argument, Monitor::whenAny(std::vector<IoEventInfo> { }));
}

TEST(default_monitor_static_api) {
    auto w = Worker::defaultWorker();
    Pipe p;
    p.write();
    CHECK(Monitor::defaultMonitor().backendName() != nullptr);
    const int e = w->sync_wait([](int fd) -> Task<int> {
        co_return co_await Monitor::wait(fd, FD_READ | FD_WRITE);
    }(p.r));
    CHECK(e & FD_READ);
}

TEST_MAIN()
