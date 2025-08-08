#include <gtest/gtest.h>
#include "../src/frames/push_promiseframe.h"
#include "test_common.h"

/*
 * The PUSH_PROMISE frame defines the following flags:

   FLAG_END_HEADERS (0x4):  When set, bit 2 indicates that this frame
      contains an entire header block (Section 4.3) and is not followed
      by any CONTINUATION frames.

      A PUSH_PROMISE frame without the FLAG_END_HEADERS flag set MUST be
      followed by a CONTINUATION frame for the same stream.  A receiver
      MUST treat the receipt of any other type of frame or a frame on a
      different stream as a connection error (Section 5.4.1) of type
      PROTOCOL_ERROR.

   FLAG_PADDED (0x8):  When set, bit 3 indicates that the Pad Length field
      and any padding that it describes are present.
 */

PushPromiseFrame* get_pp_frame() {
    auto *f = new PushPromiseFrame();
    f->flags = 0x0;
    f->stream_id = 0x00000001;
    f->reserved_pp = false;
    f->prom_stream_id = 0x12345678;
    return f;
}

TEST(PushPromiseFrameSrlz, NoPadNoHeadersNotReserved) {
    auto *f = get_pp_frame();
    f->reserved_pp = false;

    uint32_t bufsz = 13;
    const char answer[] = "\x00\x00\x04"
                          "\x05\x00"
                          "\x00\x00\x00\x01"
                          "\x12\x34\x56\x78";
    test_srlz_common(f, answer, bufsz);
}

TEST(PushPromiseFrameSrlz, NoPadNoHeadersReserved) {
    auto *f = get_pp_frame();
    f->reserved_pp = true;

    uint32_t bufsz = 13;
    const char answer[] = "\x00\x00\x04"
                          "\x05\x00"
                          "\x00\x00\x00\x01"
                          "\x92\x34\x56\x78";
    test_srlz_common(f, answer, bufsz);
}

TEST(PushPromiseFrameSrlz, PadHeaders) {
    auto *f = get_pp_frame();
    f->reserved_pp = false;
    f->flags = FLAG_END_HEADERS | FLAG_PADDED;

    f->padlen = 16;
    f->padding.insert(f->padding.begin(), f->padlen, 0);
    f->add_header(":method", "POST", HPacker::PrefixType::INDEXED_HEADER, HPacker::IndexingType::ALL);
    f->add_header(":scheme", "http", HPacker::PrefixType::INDEXED_HEADER, HPacker::IndexingType::ALL);
    f->add_header(":path", "/reqid=4", HPacker::PrefixType::LITERAL_HEADER_NEVER_INDEXED, HPacker::IndexingType::NONE);
    f->add_header(":authority", "localhost:8000", HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING, HPacker::IndexingType::NAME);

    uint32_t bufsz = 67;
    const char answer[] = "\x00\x00\x3a"
                          "\x05\x0c"
                          "\x00\x00\x00\x01"
                          "\x10"
                          "\x12\x34\x56\x78"
                          DYN_TAB_UPDATE
                          "\x83"
                          "\x86"
                          "\x10\x05:path\x08/reqid=4"
                          "\x41\x0elocalhost:8000"
                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    test_srlz_common(f, answer, bufsz);
}

typedef HPacker::PrefixType PrefType;
typedef HPacker::IndexingType IdxType;

TEST(PushPromiseFrameDesrlz, PadHeaders) {
    auto *answer = get_pp_frame();
    answer->len = 51;
    answer->reserved_pp = false;
    answer->flags = FLAG_END_HEADERS | FLAG_PADDED;

    answer->padlen = 16;
    answer->padding.insert(answer->padding.begin(), answer->padlen, 0);

    answer->add_header(":method", "POST", PrefType::INDEXED_HEADER, IdxType::ALL);
    answer->add_header(":scheme", "http", PrefType::INDEXED_HEADER, IdxType::ALL);
    answer->add_header(":path", "/reqid=4", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    answer->add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NAME);

    uint32_t insz = 60;
    char in[] = "\x00\x00\x33"
                "\x05\x0c"
                "\x00\x00\x00\x01"
                "\x10"
                "\x12\x34\x56\x78"
                "\x3f\xe1\x1f"
                "\x83"
                "\x86"
                "\x10"
                "\x84\xb9\x58\xd3\x3f"
                "\x86\x62\xc2\xf6\x34\x90\x35"
                "\x41"
                "\x8a\xa0\xe4\x1d\x13\x9d\x09\xb8\xf0\x00\x0f"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    test_desrlz_common(in, insz, answer);
}