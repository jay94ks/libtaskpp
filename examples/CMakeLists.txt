add_executable(example_basic basic.cpp)
target_link_libraries(example_basic PRIVATE taskpp::taskpp)

if (UNIX)
    add_executable(example_monitor monitor.cpp)
    target_link_libraries(example_monitor PRIVATE taskpp::taskpp)
endif()
