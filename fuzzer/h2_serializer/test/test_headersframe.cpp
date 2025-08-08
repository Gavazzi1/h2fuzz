#include "../src/hpacker/HPacker.h"
#include <gtest/gtest.h>
#include "../src/frames/frames.h"
#include "test_common.h"


TEST(HeadersFrameSrlz, Reqid4) {
    auto* f = new HeadersFrame();
    f->flags = FLAG_END_HEADERS | FLAG_PADDED | FLAG_PRIORITY;
    f->stream_id = 0x00000001;
    f->padlen = 0x20;
    f->padding.insert(f->padding.begin(), f->padlen, 0);
    f->weight = 0xFF;
    f->stream_dep = 0x01020304;
    f->add_header(":method", "POST", HPacker::PrefixType::INDEXED_HEADER, HPacker::IndexingType::ALL);
    f->add_header(":scheme", "http", HPacker::PrefixType::INDEXED_HEADER, HPacker::IndexingType::ALL);
    f->add_header(":path", "/reqid=4", HPacker::PrefixType::LITERAL_HEADER_NEVER_INDEXED, HPacker::IndexingType::NONE);
    f->add_header(":authority", "localhost:8000", HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING, HPacker::IndexingType::NAME);

    uint32_t bufsz = 84;
    const char answer[] = "\x00\x00\x4b"
                          "\x01\x2c"
                          "\x00\x00\x00\x01"
                          "\x20"
                          "\x01\x02\x03\x04"
                          "\xFF"
                          DYN_TAB_UPDATE
                          "\x83"
                          "\x86"
                          "\x10\x05:path\x08/reqid=4"
                          "\x41\x0elocalhost:8000"
                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    test_srlz_common(f, answer, bufsz);
}

typedef HPacker::PrefixType PrefType;
typedef HPacker::IndexingType IdxType;

TEST(HeadersFrameSrlz, KeyCollision) {
    /* This tests that if the concatenation of the name and value of two headers is the same, they can still be uniquely
     * identified in the HPACK table
     *
     * NOTE: "The first and newest entry in a dynamic table is at the lowest index, and the oldest entry of a dynamic
     *       table is at the highest index."
     */

    auto *hf = new HeadersFrame();  // must be dynamic because test_srlz_common frees pointer
    hf->add_header("x", "yz", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    hf->add_header("xy", "z", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    hf->add_header("x", "yz", PrefType::INDEXED_HEADER, IdxType::ALL);
    hf->add_header("xy", "z", PrefType::INDEXED_HEADER, IdxType::ALL);

    uint32_t bufsz = HDRSZ + 17;
    const char answer[] = "\x00\x00\x11"
                          "\x01\x00"
                          "\x00\x00\x00\x00"
                          DYN_TAB_UPDATE
                          "\x40\x01x\x02yz"
                          "\x40\x02xy\x01z"
                          "\xbf"
                          "\xbe";
    test_srlz_common(hf, answer, bufsz);
}

TEST(HeadersFrameSrlz, InvalidEncodingGivesRuntimeError) {
    HeadersFrame hf;
    hf.add_header(":method", "asdf", PrefType::INDEXED_HEADER, IdxType::ALL);
    hpack::HPacker hpe;
    char buf[64];

    // name in table but val not, can't have full index
    ASSERT_THROW(hf.serialize(buf, 64, &hpe, false), std::runtime_error);

    // neither name/value in table, can't have full index
    hf.reset_srlz_blk();
    hf.hdr_pairs[0].first = "asdf";
    ASSERT_THROW(hf.serialize(buf, 64, &hpe, false), std::runtime_error);

    // neither name/value in table, can't have name idxed
    hf.idx_types[0] = IdxType::NAME;
    for (auto p : {PrefType::LITERAL_HEADER_WITH_INDEXING, PrefType::LITERAL_HEADER_WITHOUT_INDEXING, PrefType::LITERAL_HEADER_NEVER_INDEXED}) {
        hf.reset_srlz_blk();
        hf.prefixes[0] = p;
        ASSERT_THROW(hf.serialize(buf, 64, &hpe, false), std::runtime_error);
    }
}

TEST(HeadersFrameDesrlz, Reqid4) {
    auto* answer = new HeadersFrame();
    answer->len = 93;
    answer->flags = FLAG_END_HEADERS | FLAG_PADDED | FLAG_PRIORITY;
    answer->stream_id = 0x00000001;
    answer->padlen = 0x10;
    answer->padding.insert(answer->padding.begin(), answer->padlen, 0);
    answer->weight = 0xFF;
    answer->stream_dep = 0x01020304;
    answer->add_header(":method", "POST", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);
    answer->add_header(":scheme", "http", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);
    answer->add_header(":path", "/reqid=4", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);
    answer->add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

    uint32_t insz = 105;
    char in[] = "\x00\x00\x5d"
                "\x01\x2c"
                "\x00\x00\x00\x01"
                "\x10"
                "\x01\x02\x03\x04"
                "\xFF"
                "\x00\x07\x3a\x6d\x65\x74\x68\x6f\x64\x04\x50\x4f\x53\x54"
                "\x00\x07\x3a\x73\x63\x68\x65\x6d\x65\x04\x68\x74\x74\x70"
                "\x00\x05\x3a\x70\x61\x74\x68\x08\x2f\x72\x65\x71\x69\x64\x3d\x34"
                "\x00\x0a\x3a\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x0e\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x38\x30\x30\x30"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    test_desrlz_common(in, insz, answer);
}

TEST(HeadersFrameDesrlz, KeyCollision) {
    /* This tests that if the concatenation of the name and value of two headers is the same, they can still be uniquely
     * identified in the HPACK table */

    uint32_t bufsz = HDRSZ + 17;
    char buf[] = "\x00\x00\x11"
                 "\x01\x00"
                 "\x00\x00\x00\x00"
                 DYN_TAB_UPDATE
                 "\x40\x01x\x02yz"
                 "\x40\x02xy\x01z"
                 "\xbf"
                 "\xbe";

    auto *answer = new HeadersFrame();
    answer->len = 17;
    answer->flags = 0x0;
    answer->stream_id = 0x0;
    answer->add_header("x", "yz", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    answer->add_header("xy", "z", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    answer->add_header("x", "yz", PrefType::INDEXED_HEADER, IdxType::ALL);
    answer->add_header("xy", "z", PrefType::INDEXED_HEADER, IdxType::ALL);

    test_desrlz_common(buf, bufsz, answer);
}