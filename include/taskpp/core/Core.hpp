#pragma once

// Everything provided by the `core` module.
// All core headers are re-exported here so `taskpp/taskpp.hpp` is the single
// global entry point (`taskpp` namespace).

#include <taskpp/core/AsyncMutex.hpp>
#include <taskpp/core/AsyncQueue.hpp>
#include <taskpp/core/Canceller.hpp>
#include <taskpp/core/Channel.hpp>
#include <taskpp/core/Task.hpp>
#include <taskpp/core/ThreadPooledWorker.hpp>
#include <taskpp/core/ThreadedWorker.hpp>
#include <taskpp/core/Timer.hpp>
#include <taskpp/core/WhenAll.hpp>
#include <taskpp/core/Worker.hpp>

#if defined(TASKPP_PLATFORM_POSIX) || defined(TASKPP_PLATFORM_WINDOWS)
#   include <taskpp/core/Monitor.hpp>
#endif
