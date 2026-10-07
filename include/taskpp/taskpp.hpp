#pragma once

// Umbrella header: pulls in every module that is linked into the build.

#include <taskpp/Config.hpp>
#include <taskpp/Exceptions.hpp>
#include <taskpp/TimeSpan.hpp>

#include <taskpp/core/Core.hpp>
#include <taskpp/socket/Socket.hpp>

#if defined(TASKPP_WITH_TLS)
#include <taskpp/tls/Tls.hpp>
#endif

#if defined(TASKPP_WITH_HTTP)
#include <taskpp/http/Http.hpp>
#endif
