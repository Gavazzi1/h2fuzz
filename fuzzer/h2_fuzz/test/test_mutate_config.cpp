
#include <gtest/gtest.h>
#include "../h2fuzzconfig.h"
#include "../proxy_config.h"
#include "../../h2_serializer/src/frames/frames.h"
#include "../../h2_serializer/src/deserializer.h"
#include "../../h2_serializer/src/hpacker/HPacker.h"
#include "../basedir.h"

#define TEST_DIR BASEDIR"/h2_fuzz/test/"

TEST(H2FuzzConfig, ParseMyConfig) {
    std::string fn = TEST_DIR "test_config_file.conf";

    H2FuzzConfig cfg;
    ASSERT_EQ(cfg.read_config(fn), 0);

    ASSERT_NE(cfg.get_fields(DATA), nullptr);
    ASSERT_NE(cfg.get_fields(HEADERS), nullptr);
    ASSERT_NE(cfg.get_fields(PRIORITY_TYPE), nullptr);
    ASSERT_NE(cfg.get_fields(RST_STREAM), nullptr);
    ASSERT_NE(cfg.get_fields(SETTINGS), nullptr);
    ASSERT_NE(cfg.get_fields(PUSH_PROMISE), nullptr);
    ASSERT_NE(cfg.get_fields(PING), nullptr);
    ASSERT_NE(cfg.get_fields(GOAWAY), nullptr);
    ASSERT_NE(cfg.get_fields(WINDOW_UPDATE), nullptr);
    ASSERT_NE(cfg.get_fields(CONTINUATION), nullptr);

    ASSERT_GT(cfg.get_fields(DATA)->size(), 0);
    ASSERT_GT(cfg.get_fields(HEADERS)->size(), 0);
    ASSERT_GT(cfg.get_fields(PRIORITY_TYPE)->size(), 0);
    ASSERT_GT(cfg.get_fields(RST_STREAM)->size(), 0);
    ASSERT_GT(cfg.get_fields(SETTINGS)->size(), 0);
    ASSERT_GT(cfg.get_fields(PUSH_PROMISE)->size(), 0);
    ASSERT_GT(cfg.get_fields(PING)->size(), 0);
    ASSERT_GT(cfg.get_fields(GOAWAY)->size(), 0);
    ASSERT_GT(cfg.get_fields(WINDOW_UPDATE)->size(), 0);
    ASSERT_GT(cfg.get_fields(CONTINUATION)->size(), 0);
}

typedef hpack::HPacker::PrefixType PrefType;
typedef hpack::HPacker::IndexingType IdxType;

TEST(H2FuzzConfig, LoadTest) {
    DataFrame df0;  // empty
    DataFrame df1;
    df1.len = 30;
    df1.flags = FLAG_PADDED;
    df1.padlen = 0x10;
    df1.padding.insert(df1.padding.begin(), df1.padlen, 0);
    const char *raw = "\x35\x0d\x0a\x41\x42\x43\x44\x45\x30\x0d\x0a\x0d\x0a";
    df1.data.insert(df1.data.end(), raw, raw + 13);

    HeadersFrame hf0;
    HeadersFrame hf1;
    hf1.len = 68;
    hf1.flags = FLAG_PADDED | FLAG_PRIORITY;
    hf1.add_header(":method", "POST", PrefType::INDEXED_HEADER, IdxType::ALL);
    hf1.add_header(":scheme", "http", PrefType::INDEXED_HEADER, IdxType::ALL);
    hf1.add_header(":path", "/reqid=4", PrefType::INDEXED_HEADER, IdxType::ALL);
    hf1.add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    hf1.padlen = 0x20;
    hf1.padding.insert(hf1.padding.begin(), hf1.padlen, 0);
    hf1.weight = 0xFF;
    hf1.stream_dep = 0x01020304;

    PriorityFrame prf;
    prf.len = 5;
    prf.exclusive = true;
    prf.stream_dep = 0x12345678;
    prf.weight = 0xff;

    RstStreamFrame rsf;
    rsf.len = 4;
    rsf.error_code = 0x13572468;

    SettingsFrame sf0;
    SettingsFrame sf1;
    sf1.len = 24;
    sf1.add_setting(SETTINGS_ENABLE_PUSH, 0);
    sf1.add_setting(SETTINGS_INITIAL_WINDOW_SIZE, 0x7fffffff);
    sf1.add_setting(SETTINGS_HEADER_TABLE_SIZE, 0x0000ffff);
    sf1.add_setting(SETTINGS_MAX_FRAME_SIZE, 0x00ffffff);

    PushPromiseFrame ppf0;
    ppf0.len = 4;
    ppf0.prom_stream_id = 0x00000001;
    PushPromiseFrame ppf1;
    ppf1.len = 51;
    ppf1.flags = FLAG_PADDED;
    ppf1.padlen = 0x10;
    ppf1.padding.insert(ppf1.padding.begin(), ppf1.padlen, 0);
    ppf1.prom_stream_id = 0x00000002;
    ppf1.add_header("hdr1", "value 1", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    ppf1.add_header("header two", "vallllue", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);

    PingFrame pif;
    pif.len = 8;
    pif.data = 0x123456789abcdef0;

    GoAway ga;
    ga.len = 12;
    ga.last_stream_id = 0x12345678;
    ga.error_code = 0x0abcdef0;
    const char *raw_ga = "\xde\xad\xbe\xef";
    ga.debug_data.insert(ga.debug_data.end(), raw_ga, raw_ga+4);

    WindowUpdate wu;
    wu.len = 4;
    wu.win_sz_inc = 0x0abbccdd;

    Continuation c;

}