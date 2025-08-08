#include <gtest/gtest.h>
#include "../src/frames/goaway.h"
#include "test_common.h"

GoAway* get_goaway() {
    auto *f = new GoAway();
    f->flags = 0x0;
    f->stream_id = 0x00000001;
    f->reserved_ga = false;
    f->last_stream_id = 0x12345678;
    f->error_code = 0x0abcdef0;
    const char *raw = "\xde\xad\xbe\xef";
    f->debug_data.insert(f->debug_data.end(), raw, raw+4);
    return f;
}

TEST(GoAwaySrlz, NoData) {
    GoAway* f = get_goaway();
    f->debug_data.resize(0);

    uint32_t bufsz = 17;
    char answer[] = "\x00\x00\x08"
                    "\x07\x00"
                    "\x00\x00\x00\x01"
                    "\x12\x34\x56\x78"
                    "\x0a\xbc\xde\xf0";
    test_srlz_common(f, answer, bufsz);
}

TEST(GoAwayDesrlz, NoDataReserved) {
    GoAway* answer = get_goaway();
    answer->len = 8;
    answer->reserved_ga = true;
    answer->debug_data.resize(0);

    uint32_t insz = 17;
    char in[] = "\x00\x00\x08"
                "\x07\x00"
                "\x00\x00\x00\x01"
                "\x92\x34\x56\x78"
                "\x0a\xbc\xde\xf0";
    test_desrlz_common(in, insz, answer);
}

TEST(GoAwaySrlz, Data) {
    GoAway* f = get_goaway();

    uint32_t bufsz = 21;
    char answer[] = "\x00\x00\x0c"
                    "\x07\x00"
                    "\x00\x00\x00\x01"
                    "\x12\x34\x56\x78"
                    "\x0a\xbc\xde\xf0"
                    "\xde\xad\xbe\xef";
    test_srlz_common(f, answer, bufsz);
}

TEST(GoAwayDesrlz, DataNoReserved) {
    GoAway* answer = get_goaway();
    answer->len = 12;
    answer->reserved_ga = false;

    uint32_t insz = 21;
    char in[] = "\x00\x00\x0c"
                "\x07\x00"
                "\x00\x00\x00\x01"
                "\x12\x34\x56\x78"
                "\x0a\xbc\xde\xf0"
                "\xde\xad\xbe\xef";
    test_desrlz_common(in, insz, answer);
}