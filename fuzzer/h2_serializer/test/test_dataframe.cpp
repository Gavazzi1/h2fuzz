
#include <gtest/gtest.h>
#include "../src/frames/frames.h"
#include "test_common.h"


DataFrame* get_dataframe() {
    auto* f = new DataFrame();
    f->flags = 0x00;
    f->stream_id = 0x00000001;
    f->padlen = 0x00;
    return f;
}

TEST(DataFrameSrlz, NoData_NoPad) {
    auto* f = get_dataframe();

    uint32_t bufsz = 9;
    const char answer[] = "\x00\x00\x00"
                          "\x00\x00"
                          "\x00\x00\x00\x01"
                          ""
                          ""
                          "";
    test_srlz_common(f, answer, bufsz);
}

TEST(DataFrameDesrlz, NoData_NoPad) {
    auto* answer = get_dataframe();
    answer->len = 0;

    uint32_t insz = 9;
    char in[] = "\x00\x00\x00"
                "\x00\x00"
                "\x00\x00\x00\x01"
                ""
                ""
                "";
    test_desrlz_common(in, insz, answer);
}

TEST(DataFrameSrlz, NoData_Pad) {
    auto* f = get_dataframe();
    f->flags = FLAG_PADDED;
    f->padlen = 0x10;
    f->padding.insert(f->padding.begin(), f->padlen, 0);

    uint32_t bufsz = 26;
    const char answer[] = "\x00\x00\x11"
                          "\x00\x08"
                          "\x00\x00\x00\x01"
                          "\x10"
                          ""
                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    test_srlz_common(f, answer, bufsz);
}

TEST(DataFrameSrlz, Data_NoPad) {
    auto* f = get_dataframe();
    f->flags = FLAG_END_STREAM;
    f->padlen = 0x00;

    const char *raw = "\x30\x0d\x0a\x0d\x0a";
    f->data.insert(f->data.end(), raw, raw+5);

    uint32_t bufsz = 14;
    const char answer[] = "\x00\x00\x05"
                          "\x00\x01"
                          "\x00\x00\x00\x01"
                          "\x30\x0d\x0a\x0d\x0a";
    test_srlz_common(f, answer, bufsz);
}

TEST(DataFrameDesrlz, Data_Pad) {
    auto *answer = get_dataframe();
    answer->len = 30;
    answer->flags = FLAG_END_STREAM | FLAG_PADDED;
    answer->padlen = 0x10;
    answer->padding.insert(answer->padding.begin(), answer->padlen, 0);

    const char *raw = "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a";
    answer->data.insert(answer->data.end(), raw, raw+13);

    uint32_t insz = 39;
    char in[] = "\x00\x00\x1e"
                "\x00\x09"
                "\x00\x00\x00\x01"
                "\x10"
                "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    test_desrlz_common(in, insz, answer);
}

TEST(DataFrameSrlz, Data_Pad) {
    auto *f = get_dataframe();
    f->flags = FLAG_END_STREAM | FLAG_PADDED;
    f->padlen = 0x10;
    f->padding.insert(f->padding.begin(), f->padlen, 0);

    const char *raw = "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a";
    f->data.insert(f->data.end(), raw, raw+13);

    uint32_t bufsz = 39;
    const char answer[] = "\x00\x00\x1e"
                          "\x00\x09"
                          "\x00\x00\x00\x01"
                          "\x10"
                          "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a"
                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    test_srlz_common(f, answer, bufsz);
}