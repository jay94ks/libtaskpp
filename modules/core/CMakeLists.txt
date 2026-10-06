add_library(taskpp_core
    src/Canceller.cpp
    src/ThreadGroup.cpp
    src/Timer.cpp
    src/Worker.cpp
)
add_library(taskpp::core ALIAS taskpp_core)

if (UNIX)
    target_sources(taskpp_core PRIVATE
        src/Monitor.cpp
        src/backends/PollBackend.cpp)

    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_sources(taskpp_core PRIVATE src/backends/EpollBackend.cpp)
    endif()
endif()

target_include_directories(taskpp_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(taskpp_core PUBLIC taskpp::common Threads::Threads)

if (MSVC)
    target_compile_options(taskpp_core PRIVATE /W4)
else()
    target_compile_options(taskpp_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if (TASKPP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
