#include <gtest/gtest.h>
#include "../src/frames/priorityframe.h"
#include "test_common.h"

PriorityFrame* get_priority_frame() {
    auto *f = new PriorityFrame();
    f->flags = 0x0;
    f->stream_id = 0x00000001;

    f->exclusive = true;
    f->stream_dep = 0x12345678;
    f->weight = 0xff;

    return f;
}

TEST(PriorityFrameSrlz, Exclusive) {
    auto *f = get_priority_frame();
    f->exclusive = true;

    uint32_t bufsz = 14;
    const char answer[] = "\x00\x00\x05"
                          "\x02\x00"
                          "\x00\x00\x00\x01"
                          "\x92\x34\x56\x78"
                          "\xff";
    test_srlz_common(f, answer, bufsz);
}

TEST(PriorityFrameSrlz, NotExclusive) {
    auto *f = get_priority_frame();
    f->exclusive = false;

    uint32_t bufsz = 14;
    const char answer[] = "\x00\x00\x05"
                          "\x02\x00"
                          "\x00\x00\x00\x01"
                          "\x12\x34\x56\x78"
                          "\xff";
    test_srlz_common(f, answer, bufsz);
}

TEST(PriorityFrameDesrlz, Exclusive) {
    auto *answer = get_priority_frame();
    answer->len = 5;
    answer->exclusive = true;

    uint32_t insz = 14;
    char in[] = "\x00\x00\x05"
                "\x02\x00"
                "\x00\x00\x00\x01"
                "\x92\x34\x56\x78"
                "\xff";
    test_desrlz_common(in, insz, answer);
}

TEST(PriorityFrameDesrlz, NotExclusive) {
    auto *answer = get_priority_frame();
    answer->len = 5;
    answer->exclusive = false;

    uint32_t insz = 14;
    char in[] = "\x00\x00\x05"
                "\x02\x00"
                "\x00\x00\x00\x01"
                "\x12\x34\x56\x78"
                "\xff";
    test_desrlz_common(in, insz, answer);
}
