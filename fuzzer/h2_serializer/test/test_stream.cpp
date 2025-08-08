#include <gtest/gtest.h>
#include "../src/frames/frames.h"
#include "test_common.h"
#include "../src/deserializer.h"

using hpack::HPacker;

TEST(StreamSrlz, Empty) {
    H2Stream s{};

    char buf[128];
    uint32_t sz = s.serialize(buf, sizeof(buf));

    ASSERT_EQ(sz, 0);
}

TEST(StreamSrlz, OneFrame) {
    DataFrame f;
    f.flags = 0x00;
    f.stream_id = 0x00000001;
    f.padlen = 0x00;

    H2Stream s{};
    s.push_back(&f);

    char buf[128];
    uint32_t sz = s.serialize(buf, sizeof(buf));

    ASSERT_EQ(sz, 9);

    const char answer[] = "\x00\x00\x00"
                          "\x00\x00"
                          "\x00\x00\x00\x01";
    EXPECT_TRUE(memcmp(buf, answer, sz) == 0);
}

TEST(StreamSrlz, DataData) {
    DataFrame f;
    f.flags = 0x00;
    f.stream_id = 0x00000001;
    f.padlen = 0x00;

    H2Stream s{};
    s.push_back(&f);
    s.push_back(&f);

    char buf[128];
    uint32_t sz = s.serialize(buf, sizeof(buf));

    ASSERT_EQ(sz, 18);

    const char answer[] = "\x00\x00\x00"
                          "\x00\x00"
                          "\x00\x00\x00\x01"
                          "\x00\x00\x00"
                          "\x00\x00"
                          "\x00\x00\x00\x01";
    EXPECT_TRUE(memcmp(buf, answer, sz) == 0);
}

TEST(StreamSrlz, ContextSharedAcrossHeaderBlocks_FullIndex) {
    /* This test ensures that if one headers block adds a header to the dynamic table, subsequent header blocks can
     * access that header by indexing the dynamic table */

    // 0x40
    // 0x05yyyyy
    // 0x05zzzzz
    HeadersFrame f1;
    f1.flags = 0x0;
    f1.stream_id = 0x00000001;
    f1.add_header("yyyyy", "zzzzz", HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING, HPacker::IndexingType::NONE);

    // 1 0111110 = 0xBE   (1 bit for indexed, 62 in binary)
    Continuation f2;
    f2.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
    f2.stream_id = 0x00000001;
    f2.add_header("yyyyy", "zzzzz", HPacker::PrefixType::INDEXED_HEADER, HPacker::IndexingType::ALL);

    H2Stream s{};
    s.push_back(&f1);
    s.push_back(&f2);

    char buf[64];
    uint32_t sz = s.serialize(buf, sizeof(buf));

    ASSERT_EQ(sz, 2*HDRSZ + 16 + 1);

    // hpack is inserting: 00111111, 11100001, 00011111 = 0x3fe11f

    const char answer[] = "\x00\x00\x10"
                          "\x01\x00"
                          "\x00\x00\x00\x01"
                          DYN_TAB_UPDATE
                          "\x40\x05yyyyy\x05zzzzz"
                          "\x00\x00\x01"
                          "\x09\x05"
                          "\x00\x00\x00\x01"
                          "\xbe";
    EXPECT_TRUE(memcmp(buf, answer, sz) == 0);
}

TEST(StreamSrlz, ContextSharedAcrossHeaderBlocks_NameIndex) {
    /* This test ensures that if one headers block adds a header to the dynamic table, subsequent header blocks can
     * access that header by indexing the dynamic table */

    HeadersFrame f1;
    f1.flags = 0x0;
    f1.stream_id = 0x00000001;
    f1.add_header("yyyyy", "zzzzz", HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING, HPacker::IndexingType::NONE);

    // 01 111110 = 0x7E   (01 bit for literal header with indexing, 62 in binary)
    // 0x05wwwww
    Continuation f2;
    f2.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
    f2.stream_id = 0x00000001;
    f2.add_header("yyyyy", "wwwww", HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING, HPacker::IndexingType::NAME);

    H2Stream s{};
    s.push_back(&f1);
    s.push_back(&f2);

    char buf[64];
    uint32_t sz = s.serialize(buf, sizeof(buf));

    ASSERT_EQ(sz, 2*HDRSZ + 3 + 13 + 7);

    const char answer[] = "\x00\x00\x10"
                          "\x01\x00"
                          "\x00\x00\x00\x01"
                          DYN_TAB_UPDATE
                          "\x40\x05yyyyy\x05zzzzz"
                          "\x00\x00\x07"
                          "\x09\x05"
                          "\x00\x00\x00\x01"
                          "\x7e"
                          "\x05wwwww";
    EXPECT_TRUE(memcmp(buf, answer, sz) == 0);
}

TEST(StreamDesrlz, OneFrame) {
    DataFrame answer;
    answer.len = 30;
    answer.flags = FLAG_END_STREAM | FLAG_PADDED;
    answer.stream_id = 0x00000001;
    answer.padlen = 0x10;
    answer.padding.insert(answer.padding.begin(), answer.padlen, 0);

    const char *raw = "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a";
    answer.data.insert(answer.data.end(), raw, raw+13);

    uint32_t insz = 39;
    char in[] = "\x00\x00\x1e"
                "\x00\x09"
                "\x00\x00\x00\x01"
                "\x10"
                "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    auto *deslz_strm = Deserializer::deserialize_stream(in, insz);
    ASSERT_EQ(deslz_strm->size(), 1);
    frame_eq((*deslz_strm)[0], &answer);

    delete (*deslz_strm)[0];
    delete deslz_strm;
}

typedef hpack::HPacker::PrefixType PrefType;
typedef hpack::HPacker::IndexingType IdxType;

TEST(StreamDesrlz, HdrDataData) {
    HeadersFrame h1;
    h1.len = 71;
    h1.flags = FLAG_END_HEADERS;
    h1.stream_id = 0x00000001;

    h1.add_header(":method", "POST", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    h1.add_header(":scheme", "http", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    h1.add_header(":path", "/reqid=4", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    h1.add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);

    DataFrame d1;
    d1.len = 30;
    d1.flags = FLAG_PADDED;
    d1.stream_id = 0x00000001;
    d1.padlen = 0x10;
    d1.padding.insert(d1.padding.begin(), d1.padlen, 0);
    const char *data1 = "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a";
    d1.data.insert(d1.data.end(), data1, data1+13);

    DataFrame d2;
    d2.len = 5;
    d2.flags = FLAG_END_STREAM;
    d2.stream_id = 0x00000001;
    d2.padlen = 0x00;
    const char *data2 = "\x30\x0d\x0a\x0d\x0a";
    d2.data.insert(d2.data.end(), data2, data2+5);

    uint32_t insz = 80 + 39 + 14;
    char in[] = "\x00\x00\x47"
                "\x01\x04"
                "\x00\x00\x00\x01"
                "\x00\x07\x3a\x6d\x65\x74\x68\x6f\x64\x04\x50\x4f\x53\x54"
                "\x00\x07\x3a\x73\x63\x68\x65\x6d\x65\x04\x68\x74\x74\x70"
                "\x00\x05\x3a\x70\x61\x74\x68\x08\x2f\x72\x65\x71\x69\x64\x3d\x34"
                "\x00\x0a\x3a\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x0e\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x38\x30\x30\x30"
                ""
                "\x00\x00\x1e"
                "\x00\x08"
                "\x00\x00\x00\x01"
                "\x10"
                "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                ""
                "\x00\x00\x05"
                "\x00\x01"
                "\x00\x00\x00\x01"
                "\x30\x0d\x0a\x0d\x0a";

    auto *deslz_strm = Deserializer::deserialize_stream(in, insz);
    ASSERT_EQ(deslz_strm->size(), 3);
    frame_eq((*deslz_strm)[0], &h1);
    frame_eq((*deslz_strm)[1], &d1);
    frame_eq((*deslz_strm)[2], &d2);

    for (Frame *f : *deslz_strm) {
        delete f;
    }
    delete deslz_strm;
}

TEST(StreamDesrlz, ContextSharedAcrossHeaderBlocks_FullIndex) {
    /* This test ensures that if one headers block adds a header to the dynamic table, subsequent header blocks can
     * access that header by indexing the dynamic table */

    uint32_t insz = 2*HDRSZ + 3 + 13 + 1;
    char in[] = "\x00\x00\x10"
                "\x01\x00"
                "\x00\x00\x00\x01"
                DYN_TAB_UPDATE
                "\x40\x05yyyyy\x05zzzzz"
                "\x00\x00\x01"
                "\x09\x05"
                "\x00\x00\x00\x01"
                "\xbe";

    HeadersFrame f1;
    f1.len = 16;
    f1.flags = 0x0;
    f1.stream_id = 0x00000001;
    f1.add_header("yyyyy", "zzzzz", HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING, HPacker::IndexingType::NONE);

    Continuation f2;
    f2.len = 1;
    f2.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
    f2.stream_id = 0x00000001;
    f2.add_header("yyyyy", "zzzzz", HPacker::PrefixType::INDEXED_HEADER, HPacker::IndexingType::ALL);

    auto *deslz_strm = Deserializer::deserialize_stream(in, insz);
    ASSERT_EQ(deslz_strm->size(), 2);
    frame_eq((*deslz_strm)[0], &f1);
    frame_eq((*deslz_strm)[1], &f2);

    for (Frame *f : *deslz_strm) {
        delete f;
    }
    delete deslz_strm;
}

TEST(StreamDesrlz, ContextSharedAcrossHeaderBlocks_NameIndex) {
    /* This test ensures that if one headers block adds a header to the dynamic table, subsequent header blocks can
     * access that header by indexing the dynamic table */

    HeadersFrame f1;
    f1.len = 16;
    f1.flags = 0x0;
    f1.stream_id = 0x00000001;
    f1.add_header("yyyyy", "zzzzz", HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING, HPacker::IndexingType::NONE);

    Continuation f2;
    f2.len = 7;
    f2.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
    f2.stream_id = 0x00000001;
    f2.add_header("yyyyy", "wwwww", HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING, HPacker::IndexingType::NAME);

    uint32_t insz = 2*HDRSZ + 3 + 13 + 7;
    const char in[] = "\x00\x00\x10"
                      "\x01\x00"
                      "\x00\x00\x00\x01"
                      DYN_TAB_UPDATE
                      "\x40\x05yyyyy\x05zzzzz"
                      "\x00\x00\x07"
                      "\x09\x05"
                      "\x00\x00\x00\x01"
                      "\x7e"
                      "\x05wwwww";

    auto *deslz_strm = Deserializer::deserialize_stream(in, insz);
    ASSERT_EQ(deslz_strm->size(), 2);
    frame_eq((*deslz_strm)[0], &f1);
    frame_eq((*deslz_strm)[1], &f2);

    for (Frame *f : *deslz_strm) {
        delete f;
    }
    delete deslz_strm;
}