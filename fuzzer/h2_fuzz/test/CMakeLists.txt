add_executable(fuzz_unit main.cpp ../proxy_config.cpp h1_parser_test.cpp hashcomp_test.cpp test_mutator.cpp test_crossover.cpp
        ../../h2_serializer/test/test_common.cpp ../../h2_serializer/src/frames/common/utils.cpp test_mutate_config.cpp
        ../h2fuzzconfig.cpp test_callback.cpp ../callbacks.cpp test_normalizer.cpp test_filter_parse.cpp test_chunkparser.cpp)
target_link_libraries(fuzz_unit gtest nezha pthread hpack fuzzy config++)

add_executable(stress_test stress_test.cpp ../h2fuzzconfig.cpp ../proxy_config.cpp ../callbacks.cpp
        ../../h2_serializer/src/frames/common/utils.cpp)
target_link_libraries(stress_test config++ hpack)