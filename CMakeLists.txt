cmake_minimum_required(VERSION 3.20)
project(libtaskpp VERSION 0.1.0 LANGUAGES C CXX)

if (NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(TASKPP_BUILD_TESTS "Build libtaskpp tests" ${PROJECT_IS_TOP_LEVEL})
option(TASKPP_BUILD_EXAMPLES "Build libtaskpp examples" ${PROJECT_IS_TOP_LEVEL})

find_package(Threads REQUIRED)

if (TASKPP_BUILD_TESTS)
    enable_testing()
endif()

# --> common headers shared by every module (include/taskpp).
add_library(taskpp_common INTERFACE)
add_library(taskpp::common ALIAS taskpp_common)
target_include_directories(taskpp_common INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(taskpp_common INTERFACE cxx_std_20)

# --> third-party deps (static, built from source, never modified).
set(CARES_STATIC ON CACHE BOOL "" FORCE)
set(CARES_SHARED OFF CACHE BOOL "" FORCE)
set(CARES_STATIC_PIC ON CACHE BOOL "" FORCE)
set(CARES_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CARES_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/c-ares)

# --> modules (modules/<name>), each produces `taskpp::<name>`.
set(TASKPP_MODULES core socket)
foreach (module IN LISTS TASKPP_MODULES)
    add_subdirectory(modules/${module})
endforeach()

# --> everything.
add_library(taskpp INTERFACE)
add_library(taskpp::taskpp ALIAS taskpp)
foreach (module IN LISTS TASKPP_MODULES)
    target_link_libraries(taskpp INTERFACE taskpp::${module})
endforeach()

if (TASKPP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
