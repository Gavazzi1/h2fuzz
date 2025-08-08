
#include <gtest/gtest.h>
#include "test_common.h"
#include "../src/hpacker/HPacker.h"

TEST(FrameCopy, DataFrame) {
    auto *answer = new DataFrame();
    answer->flags = 0x00;
    answer->stream_id = 0x00000001;
    answer->len = 30;
    answer->flags = FLAG_END_STREAM | FLAG_PADDED;
    answer->padlen = 0x10;
    answer->padding.insert(answer->padding.begin(), answer->padlen, 0);

    const char *data = "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a";
    answer->data.insert(answer->data.end(), data, data+13);

    auto *copy = FrameCopier::copy_frame(answer);
    frame_eq(copy, answer);
    delete answer;
    delete copy;
}

typedef hpack::HPacker::PrefixType PrefType;
typedef hpack::HPacker::IndexingType IdxType;

TEST(FrameCopy, HeadersFrame) {
    auto* answer = new HeadersFrame();
    answer->len = 71;
    answer->flags = FLAG_END_HEADERS;
    answer->stream_id = 0x00000001;

    answer->add_header(":method", "POST", PrefType::INDEXED_HEADER, IdxType::ALL);
    answer->add_header(":scheme", "http", PrefType::INDEXED_HEADER, IdxType::ALL);
    answer->add_header(":path", "/reqid=4", PrefType::INDEXED_HEADER, IdxType::ALL);
    answer->add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::ALL);

    auto *copy = FrameCopier::copy_frame(answer);
    frame_eq(copy, answer);
    delete answer;
    delete copy;
}

TEST(FrameCopy, PriorityFrame) {
    auto *f = new PriorityFrame();
    f->flags = 0x0;
    f->stream_id = 0x00000001;

    f->exclusive = true;
    f->stream_dep = 0x12345678;
    f->weight = 0xff;
    f->len = 5;
    f->exclusive = true;

    auto *copy = FrameCopier::copy_frame(f);
    frame_eq(f, copy);
    delete f;
    delete copy;
}

TEST(FrameCopy, RstStreamFrame) {
    auto *f = new RstStreamFrame();
    f->flags = 0x0;
    f->stream_id = 0x00000001;
    f->error_code = 0x12345678;
    f->len = 4;

    auto *copy = FrameCopier::copy_frame(f);
    frame_eq(copy, f);
    delete f;
    delete copy;
}

TEST(FrameCopy, SettingsFrame) {
    auto *f = new SettingsFrame();
    f->flags = 0x00;
    f->stream_id = 0x00000001;
    f->len = 24;
    f->add_setting(SETTINGS_ENABLE_PUSH, 0);
    f->add_setting(SETTINGS_INITIAL_WINDOW_SIZE, 0x7fffffff);
    f->add_setting(SETTINGS_HEADER_TABLE_SIZE, 0x0000ffff);
    f->add_setting(SETTINGS_MAX_FRAME_SIZE, 0x00ffffff);

    auto *copy = FrameCopier::copy_frame(f);
    frame_eq(copy, f);
    delete f;
    delete copy;
}

TEST(FrameCopy, PushPromiseFrame) {
    auto *f = new PushPromiseFrame();
    f->flags = 0x0;
    f->stream_id = 0x00000001;
    f->reserved_pp = false;
    f->prom_stream_id = 0x12345678;
    f->len = 51;
    f->reserved_pp = false;
    f->flags = FLAG_END_HEADERS | FLAG_PADDED;
    f->padlen = 16;
    f->padding.insert(f->padding.begin(), f->padlen, 0);
    f->add_header(":method", "POST", PrefType::INDEXED_HEADER, IdxType::ALL);
    f->add_header(":scheme", "http", PrefType::INDEXED_HEADER, IdxType::ALL);
    f->add_header(":path", "/reqid=4", PrefType::INDEXED_HEADER, IdxType::ALL);
    f->add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::ALL);

    auto *copy = FrameCopier::copy_frame(f);
    frame_eq(copy, f);
    delete f;
    delete copy;
}

TEST(FrameCopy, PingFrame) {
    auto *answer = new PingFrame();
    answer->len = 8;
    answer->flags = 0x0;
    answer->stream_id = 0x00000001;
    answer->data = 0x123456789abcdef0;

    auto *copy = FrameCopier::copy_frame(answer);
    frame_eq(copy, answer);
    delete answer;
    delete copy;
}

TEST(FrameCopy, GoAway) {
    auto *f = new GoAway();
    f->flags = 0x0;
    f->stream_id = 0x00000001;
    f->reserved_ga = false;
    f->last_stream_id = 0x12345678;
    f->error_code = 0x0abcdef0;
    const char *raw = "\xde\xad\xbe\xef";
    f->debug_data.insert(f->debug_data.end(), raw, raw+4);
    f->len = 12;

    auto *copy = FrameCopier::copy_frame(f);
    frame_eq(copy, f);
    delete f;
    delete copy;
}

TEST(FrameCopy, WindowUpdate) {
    auto *f = new WindowUpdate();
    f->flags = 0x0;
    f->stream_id = 0x00000001;
    f->win_sz_inc = 0x0abbccdd;
    f->len = 4;

    auto *copy = FrameCopier::copy_frame(f);
    frame_eq(copy, f);
    delete f;
    delete copy;
}

TEST(FrameCopy, Continuation) {
    auto *f = new Continuation();
    f->len = 71;
    f->flags = FLAG_END_HEADERS;
    f->stream_id = 0x00000001;

    f->add_header(":method", "POST", PrefType::INDEXED_HEADER, IdxType::ALL);
    f->add_header(":scheme", "http", PrefType::INDEXED_HEADER, IdxType::ALL);
    f->add_header(":path", "/reqid=4", PrefType::INDEXED_HEADER, IdxType::ALL);
    f->add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::ALL);

    auto *copy = FrameCopier::copy_frame(f);
    frame_eq(copy, f);
    delete copy;
    delete f;
}