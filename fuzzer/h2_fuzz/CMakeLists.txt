
add_subdirectory(test)

add_executable(h2_fuzz main.cc callbacks.cpp proxy_config.cpp h2mutator.cpp h2fuzzconfig.cpp)
target_link_libraries(h2_fuzz nezha pthread h2srlz ssl crypto fuzzy config++)

add_executable(test_proxies_up test_proxies_up.cpp proxy_config.cpp callbacks.cpp)
target_link_libraries(test_proxies_up pthread h2srlz config++)

add_executable(send_one_proxy send_one_proxy.cpp proxy_config.cpp callbacks.cpp)
target_link_libraries(send_one_proxy pthread h2srlz config++)

add_executable(build_and_send_stream build_and_send_stream.cpp proxy_config.cpp callbacks.cpp)
target_link_libraries(build_and_send_stream pthread h2srlz config++)
