add_executable(example_basic basic.cpp)
target_link_libraries(example_basic PRIVATE taskpp::taskpp)

if (UNIX)
    add_executable(example_monitor monitor.cpp)
    target_link_libraries(example_monitor PRIVATE taskpp::taskpp)
endif()

add_executable(example_socket_echo socket_echo.cpp)
target_link_libraries(example_socket_echo PRIVATE taskpp::taskpp)

add_executable(example_tls_probe tls_probe.cpp)
target_link_libraries(example_tls_probe PRIVATE taskpp::taskpp)
