#include <gtest/gtest.h>
#include "test_common.h"
#include "../src/frames/window_updateframe.h"

WindowUpdate* get_window_update() {
    auto *f = new WindowUpdate();
    f->flags = 0x0;
    f->stream_id = 0x00000001;
    f->win_sz_inc = 0x0abbccdd;
    return f;
}

TEST(WindowUpdateSrlz, HasFieldNoReserved) {
    auto *f = get_window_update();

    uint32_t bufsz = 13;
    char answer[] = "\x00\x00\x04"
                    "\x08\x00"
                    "\x00\x00\x00\x01"
                    "\x0a\xbb\xcc\xdd";
    test_srlz_common(f, answer, bufsz);
}

TEST(WindowUpdateSrlz, HasFieldReserved) {
    auto *f = get_window_update();
    f->reserved_wu = true;

    uint32_t bufsz = 13;
    char answer[] = "\x00\x00\x04"
                    "\x08\x00"
                    "\x00\x00\x00\x01"
                    "\x8a\xbb\xcc\xdd";
    test_srlz_common(f, answer, bufsz);
}

TEST(WindowUpdateDesrlz, HasFieldNoReserved) {
    auto *answer = get_window_update();
    answer->len = 4;

    uint32_t insz = 13;
    char in[] = "\x00\x00\x04"
                    "\x08\x00"
                    "\x00\x00\x00\x01"
                    "\x0a\xbb\xcc\xdd";
    test_desrlz_common(in, insz, answer);
}

TEST(WindowUpdateDesrlz, HasFieldReserved) {
    auto *answer = get_window_update();
    answer->len = 4;
    answer->reserved_wu = true;

    uint32_t insz = 13;
    char in[] = "\x00\x00\x04"
                    "\x08\x00"
                    "\x00\x00\x00\x01"
                    "\x8a\xbb\xcc\xdd";
    test_desrlz_common(in, insz, answer);
}