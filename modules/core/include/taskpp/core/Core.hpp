#pragma once

// Everything provided by the `core` module.

#include <taskpp/core/AsyncQueue.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Task.hpp>
#include <taskpp/core/ThreadPooledWorker.hpp>
#include <taskpp/core/ThreadedWorker.hpp>
#include <taskpp/core/Timer.hpp>
#include <taskpp/core/Worker.hpp>

#if defined(TASKPP_PLATFORM_POSIX)
#   include <taskpp/core/Monitor.hpp>
#endif
