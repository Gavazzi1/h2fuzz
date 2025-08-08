
add_executable(unit_test main.cpp test_dataframe.cpp test_headersframe.cpp test_settingsframe.cpp test_priorityframe.cpp
        test_rst_streamframe.cpp test_push_promiseframe.cpp test_pingframe.cpp test_goawayframe.cpp test_window_updateframe.cpp
        test_common.cpp test_continuation.cpp test_stream.cpp test_utils.cpp
        test_frame_copy.cpp)
target_link_libraries(unit_test h2srlz gtest pthread)
