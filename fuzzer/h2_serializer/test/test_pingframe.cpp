#include <gtest/gtest.h>
#include "../src/frames/pingframe.h"
#include "test_common.h"

TEST(PingFrameSrlz, Simple) {
    auto *f = new PingFrame();
    f->flags = 0x0;
    f->stream_id = 0x00000001;
    f->data = 0x123456789abcdef0;

    uint32_t bufsz = 17;
    char answer[] = "\x00\x00\x08"
                    "\x06\x00"
                    "\x00\x00\x00\x01"
                    "\x12\x34\x56\x78\x9a\xbc\xde\xf0";
    test_srlz_common(f, answer, bufsz);
}

TEST(PingFrameDesrlz, Simple) {
    auto *answer = new PingFrame();
    answer->len = 8;
    answer->flags = 0x0;
    answer->stream_id = 0x00000001;
    answer->data = 0x123456789abcdef0;

    uint32_t insz = 17;
    char in[] = "\x00\x00\x08"
                "\x06\x00"
                "\x00\x00\x00\x01"
                "\x12\x34\x56\x78\x9a\xbc\xde\xf0";
    test_srlz_common(answer, in, insz);
}