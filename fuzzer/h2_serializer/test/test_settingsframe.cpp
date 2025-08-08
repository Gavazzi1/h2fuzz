
#include <gtest/gtest.h>
#include "../src/frames/frames.h"
#include "test_common.h"

SettingsFrame* get_settings_frame() {
    auto *f = new SettingsFrame();
    f->flags = 0x00;
    f->stream_id = 0x00000001;
    return f;
}

TEST(SettingsFrameSrlz, Empty) {
    auto *f = get_settings_frame();

    uint32_t bufsz = 9;
    const char answer[] = "\x00\x00\x00"
                          "\x04\x00"
                          "\x00\x00\x00\x01";
    test_srlz_common(f, answer, bufsz);
}

TEST(SettingsFrameDesrlz, Empty) {
    auto *answer = get_settings_frame();
    answer->len = 0;

    uint32_t insz = 9;
    char in[] = "\x00\x00\x00"
                "\x04\x00"
                "\x00\x00\x00\x01";
    test_desrlz_common(in, insz, answer);
}

TEST(SettingsFrameSrlz, Reqid4) {
    auto *f = get_settings_frame();

    f->add_setting(SETTINGS_ENABLE_PUSH, 0);
    f->add_setting(SETTINGS_INITIAL_WINDOW_SIZE, 0x7fffffff);
    f->add_setting(SETTINGS_HEADER_TABLE_SIZE, 0x0000ffff);
    f->add_setting(SETTINGS_MAX_FRAME_SIZE, 0x00ffffff);

    uint32_t bufsz = 33;
    const char answer[] = "\x00\x00\x18"
                          "\x04\x00"
                          "\x00\x00\x00\x01"
                          "\x00\x02"
                          "\x00\x00\x00\x00"
                          "\x00\x04"
                          "\x7f\xff\xff\xff"
                          "\x00\x01"
                          "\x00\x00\xff\xff"
                          "\x00\x05"
                          "\x00\xff\xff\xff";
    test_srlz_common(f, answer, bufsz);
}

TEST(SettingsFrameDesrlz, Reqid4) {
    auto *answer = get_settings_frame();
    answer->len = 24;

    answer->add_setting(SETTINGS_ENABLE_PUSH, 0);
    answer->add_setting(SETTINGS_INITIAL_WINDOW_SIZE, 0x7fffffff);
    answer->add_setting(SETTINGS_HEADER_TABLE_SIZE, 0x0000ffff);
    answer->add_setting(SETTINGS_MAX_FRAME_SIZE, 0x00ffffff);

    uint32_t insz = 33;
    char in[] = "\x00\x00\x18"
                "\x04\x00"
                "\x00\x00\x00\x01"
                "\x00\x02"
                "\x00\x00\x00\x00"
                "\x00\x04"
                "\x7f\xff\xff\xff"
                "\x00\x01"
                "\x00\x00\xff\xff"
                "\x00\x05"
                "\x00\xff\xff\xff";
    test_desrlz_common(in, insz, answer);
}