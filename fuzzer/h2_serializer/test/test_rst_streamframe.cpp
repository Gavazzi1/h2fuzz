#include <gtest/gtest.h>
#include "../src/frames/rst_streamframe.h"
#include "test_common.h"

RstStreamFrame* get_rst_stream_frame() {
    auto *f = new RstStreamFrame();
    f->flags = 0x0;
    f->stream_id = 0x00000001;
    f->error_code = 0x12345678;
    return f;
}

TEST(RstStreamFrameSrlz, HasCode) {
    auto *f = get_rst_stream_frame();

    uint32_t bufsz = 13;
    const char answer[] = "\x00\x00\x04"
                          "\x03\x00"
                          "\x00\x00\x00\x01"
                          "\x12\x34\x56\x78";
    test_srlz_common(f, answer, bufsz);
}

TEST(RstStreamFrameDesrlz, HasCode) {
    auto *answer = get_rst_stream_frame();
    answer->len = 4;

    uint32_t insz = 13;
    char in[] = "\x00\x00\x04"
                "\x03\x00"
                "\x00\x00\x00\x01"
                "\x12\x34\x56\x78";
    test_desrlz_common(in, insz, answer);
}

TEST(RstStreamFrameSrlz, ReservedBit) {
    auto *f = get_rst_stream_frame();
    f->reserved = true;
    f->stream_id = 0x00000001;

    uint32_t bufsz = 13;
    const char answer[] = "\x00\x00\x04"
                          "\x03\x00"
                          "\x80\x00\x00\x01"
                          "\x12\x34\x56\x78";
    test_srlz_common(f, answer, bufsz);
}