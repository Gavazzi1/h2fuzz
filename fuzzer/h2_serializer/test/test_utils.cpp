
#include <gtest/gtest.h>
#include "../src/frames/common/utils.h"

TEST(Utils, buf_to_uint16_no_sign_bits) {
    char buf[] = "\x11\x22";
    ASSERT_EQ(Utils::buf_to_uint16(buf), 4386);
}

TEST(Utils, buf_to_uint16_sign_bits) {
    char buf[] = "\xff\xff";
    ASSERT_EQ(Utils::buf_to_uint16(buf), 65535);
}

TEST(Utils, buf_to_uint32_no_sign_bits) {
    char buf[] = "\x11\x22\x33\x44";
    ASSERT_EQ(Utils::buf_to_uint32(buf), 287454020);
}

TEST(Utils, buf_to_uint32_sign_bits) {
    char buf[] = "\xff\xff\xff\xff";
    ASSERT_EQ(Utils::buf_to_uint32(buf), 4294967295);
}

TEST(Utils, buf_to_uint64_no_sign_bits) {
    char buf[] = "\x11\x22\x33\x44\x55\x66\x77\x88";
    ASSERT_EQ(Utils::buf_to_uint64(buf), 1234605616436508552);
}

TEST(Utils, buf_to_uint64_sign_bits) {
    char buf[] = "\xff\xff\xff\xff\xff\xff\xff\xff";
    ASSERT_EQ(Utils::buf_to_uint64(buf), UINT64_MAX);
}