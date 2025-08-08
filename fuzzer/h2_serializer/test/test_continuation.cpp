#include <gtest/gtest.h>
#include "../src/frames/continuation.h"
#include "test_common.h"

TEST(Continuation, SrlzEmpty) {
    auto* f = new Continuation();
    f->flags = FLAG_END_HEADERS;
    f->stream_id = 0x00000001;

    uint32_t bufsz = 9;
    const char answer[] = "\x00\x00\x00"
                          "\x09\x04"
                          "\x00\x00\x00\x01";
    test_srlz_common(f, answer, bufsz);
}

TEST(Continuation, SrlzHeaders) {
    auto* f = new Continuation();
    f->flags = FLAG_END_HEADERS;
    f->stream_id = 0x00000001;

    f->add_header(":method", "POST", HPacker::PrefixType::INDEXED_HEADER, HPacker::IndexingType::ALL);
    f->add_header(":scheme", "http", HPacker::PrefixType::INDEXED_HEADER, HPacker::IndexingType::ALL);
    f->add_header(":path", "/reqid=4", HPacker::PrefixType::LITERAL_HEADER_NEVER_INDEXED, HPacker::IndexingType::NONE);
    f->add_header(":authority", "localhost:8000", HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING, HPacker::IndexingType::NAME);

    uint32_t bufsz = 46;
    const char answer[] = "\x00\x00\x25"
                          "\x09\x04"
                          "\x00\x00\x00\x01"
                          DYN_TAB_UPDATE
                          "\x83"
                          "\x86"
                          "\x10\x05:path\x08/reqid=4"
                          "\x41\x0elocalhost:8000";
    test_srlz_common(f, answer, bufsz);
}

TEST(Continuation, DesrlzEmpty) {
    auto* answer = new Continuation();
    answer->len = 0;
    answer->flags = FLAG_END_HEADERS;
    answer->stream_id = 0x00000001;

    uint32_t insz = 9;
    char in[] = "\x00\x00\x00"
                "\x09\x04"
                "\x00\x00\x00\x01";
    test_desrlz_common(in, insz, answer);
}

typedef HPacker::PrefixType PrefType;
typedef HPacker::IndexingType IdxType;

TEST(Continuation, DesrlzHeaders) {
    auto* answer = new Continuation();
    answer->len = 71;
    answer->flags = FLAG_END_HEADERS;
    answer->stream_id = 0x00000001;

    answer->add_header(":method", "POST", PrefType::INDEXED_HEADER, IdxType::ALL);
    answer->add_header(":scheme", "http", PrefType::INDEXED_HEADER, IdxType::ALL);
    answer->add_header(":path", "/reqid=4", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    answer->add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NAME);

    uint32_t insz = 80;
    char in[] = "\x00\x00\x47"
                "\x09\x04"
                "\x00\x00\x00\x01"
                "\x00\x07\x3a\x6d\x65\x74\x68\x6f\x64\x04\x50\x4f\x53\x54"
                "\x00\x07\x3a\x73\x63\x68\x65\x6d\x65\x04\x68\x74\x74\x70"
                "\x00\x05\x3a\x70\x61\x74\x68\x08\x2f\x72\x65\x71\x69\x64\x3d\x34"
                "\x00\x0a\x3a\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x0e\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x38\x30\x30\x30";
    test_desrlz_common(in, insz, answer);
}