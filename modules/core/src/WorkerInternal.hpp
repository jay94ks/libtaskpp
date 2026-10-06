#pragma once
#include <taskpp/core/Worker.hpp>

namespace taskpp::detail {

Worker* currentWorkerRaw() noexcept;
Worker* exchangeCurrentWorker(Worker* worker) noexcept;

} // namespace taskpp::detail
