
#include <gtest/gtest.h>
#include <iostream>
#include "../src/frames/frames.h"
#include "test_common.h"
#include "../src/deserializer.h"

/**
 * Serializes the given Frame and compares the serialized string to the given (correct) answer
 */
void test_srlz_common(Frame *f, const char *answer, uint32_t bufsz, bool print) {
    hpack::HPacker hpe;
    char buf[bufsz];
    uint32_t sz = f->serialize(buf, bufsz, &hpe, false);

    if (print) {
        for (int i = 0; i < sz; i++) {
            printf("\\x%02x",buf[i] & 0xff);
        }
        printf("\n");
    }

    ASSERT_EQ(sz, bufsz);
    for (int i = 0; i < sz; ++i) {
        EXPECT_EQ(buf[i], answer[i]) << "Byte: " << i << ". Expected " << answer[i] << ". Given " << buf[i] << std::endl;
    }
    //EXPECT_TRUE(memcmp(buf, answer, bufsz) == 0);

    delete f;
}

/**
 * Compares the Padded fields of the given two frames
 */
void test_desrlz_padded(Frame *test, Frame *answer) {
    auto *desrlz_pf = dynamic_cast<Padded *>(test);
    auto *answer_pf = dynamic_cast<Padded *>(answer);

    if (answer->flags & FLAG_PADDED) {
        ASSERT_EQ(desrlz_pf->padlen, answer_pf->padlen);
        ASSERT_EQ(desrlz_pf->padding, answer_pf->padding);
    }
}

/**
 * Compares the DepWeight fields of the given two frames
 */
void test_desrlz_depweight(Frame *test, Frame *answer) {
    auto *desrlz_dwf = dynamic_cast<DepWeight *>(test);
    auto *answer_dwf = dynamic_cast<DepWeight *>(answer);

    ASSERT_EQ(desrlz_dwf->exclusive, answer_dwf->exclusive);
    ASSERT_EQ(desrlz_dwf->stream_dep, answer_dwf->stream_dep);
    ASSERT_EQ(desrlz_dwf->weight, answer_dwf->weight);

}

/**
 * Compares the Headers fields of the given two frames
 */
void test_desrlz_rawheaders(Frame *test, Frame *answer) {
    auto *desrlz_hf = dynamic_cast<Headers *>(test);
    auto *answer_hf = dynamic_cast<Headers *>(answer);

    ASSERT_EQ(desrlz_hf->hdr_pairs.size(), answer_hf->hdr_pairs.size());
    for (int i = 0; i < desrlz_hf->hdr_pairs.size(); ++i) {
        ASSERT_EQ(desrlz_hf->hdr_pairs[0].first, answer_hf->hdr_pairs[0].first);
        ASSERT_EQ(desrlz_hf->hdr_pairs[0].second, answer_hf->hdr_pairs[0].second);
    }
}

/**
 * Compares the DataFrame fields of the given two frames
 */
void test_desrlz_dataframe(Frame *out, Frame *answer) {
    auto *desrlz_df = dynamic_cast<DataFrame *>(out);
    auto *answer_df = dynamic_cast<DataFrame *>(answer);

    test_desrlz_padded(desrlz_df, answer_df);
    ASSERT_EQ(desrlz_df->data, answer_df->data);
}

/**
 * Compares the HeadersFrame fields of the given two frames
 */
void test_desrlz_headersframe(Frame *out, Frame *answer) {
    auto *desrlz_hf = dynamic_cast<HeadersFrame *>(out);
    auto *answer_hf = dynamic_cast<HeadersFrame *>(answer);

    test_desrlz_padded(desrlz_hf, answer_hf);
    test_desrlz_depweight(desrlz_hf, answer_hf);
    test_desrlz_rawheaders(desrlz_hf, answer_hf);
}

/**
 * Compares the PriorityFrame fields of the given two frames
 */
void test_desrlz_priorityframe(Frame *out, Frame *answer) {
    auto *desrlz_pf = dynamic_cast<PriorityFrame *>(out);
    auto *answer_pf = dynamic_cast<PriorityFrame *>(answer);

    test_desrlz_depweight(desrlz_pf, answer_pf);
}

/**
 * Compares the RstStreamFrame fields of the given two frames
 */
void test_desrlz_rst_streamframe(Frame *out, Frame *answer) {
    auto *desrlz_rsf = dynamic_cast<RstStreamFrame *>(out);
    auto *answer_rsf = dynamic_cast<RstStreamFrame *>(answer);

    ASSERT_EQ(desrlz_rsf->error_code, answer_rsf->error_code);
}

/**
 * Compares the SettingsFrame fields of the given two frames
 */
void test_desrlz_settingsframe(Frame *out, Frame *answer) {
    auto *desrlz_sf = dynamic_cast<SettingsFrame *>(out);
    auto *answer_sf = dynamic_cast<SettingsFrame *>(answer);

    ASSERT_EQ(desrlz_sf->settings.size(), answer_sf->settings.size());
    for (int i = 0; i < answer_sf->settings.size(); ++i) {
        ASSERT_EQ(desrlz_sf->settings[i], answer_sf->settings[i]);
    }
}

/**
 * Compares the PushPromiseFrame fields of the given two frames
 */
void test_desrlz_pushpromiseframe(Frame *out, Frame *answer) {
    auto *desrlz_ppf = dynamic_cast<PushPromiseFrame *>(out);
    auto *answer_ppf = dynamic_cast<PushPromiseFrame *>(answer);

    test_desrlz_padded(out, answer);
    test_desrlz_rawheaders(out, answer);
    ASSERT_EQ(desrlz_ppf->reserved_pp, answer_ppf->reserved_pp);
    ASSERT_EQ(desrlz_ppf->prom_stream_id, answer_ppf->prom_stream_id);
}

/**
 * Compares the PingFrame fields of the given two frames
 */
void test_desrlz_pingframe(Frame *out, Frame *answer) {
    auto *desrlz_pf = dynamic_cast<PingFrame *>(out);
    auto *answer_pf = dynamic_cast<PingFrame *>(answer);

    ASSERT_EQ(desrlz_pf->data, answer_pf->data);
}

/**
 * Compares the GoAwayFrame fields of the given two frames
 */
void test_desrlz_goaway(Frame *out, Frame *answer) {
    auto *desrlz_gaf = dynamic_cast<GoAway *>(out);
    auto *answer_gaf = dynamic_cast<GoAway *>(answer);

    ASSERT_EQ(desrlz_gaf->reserved_ga, answer_gaf->reserved_ga);
    ASSERT_EQ(desrlz_gaf->last_stream_id, answer_gaf->last_stream_id);
    ASSERT_EQ(desrlz_gaf->error_code, answer_gaf->error_code);
    ASSERT_EQ(desrlz_gaf->debug_data, answer_gaf->debug_data);
}

/**
 * Compares the WindowUpdateFrame fields of the given two frames
 */
void test_desrlz_window_updateframe(Frame *out, Frame *answer) {
    auto *desrlz_wuf = dynamic_cast<WindowUpdate *>(out);
    auto *answer_wuf = dynamic_cast<WindowUpdate *>(answer);

    ASSERT_EQ(desrlz_wuf->reserved_wu, answer_wuf->reserved_wu);
    ASSERT_EQ(desrlz_wuf->win_sz_inc, answer_wuf->win_sz_inc);
}

/**
 * Compares the Continuation fields of the given two frames
 */
void test_desrlz_continuation(Frame *out, Frame *answer) {
    auto *desrlz_cf = dynamic_cast<Continuation *>(out);
    auto *answer_cf = dynamic_cast<Continuation *>(answer);

    test_desrlz_rawheaders(desrlz_cf, answer_cf);
}

/**
 * Tests whether the given two frames are equal
 */
void frame_eq(Frame *out, Frame *answer) {
    // compare common frame fields
    ASSERT_EQ(out->len, answer->len);
    ASSERT_EQ(out->type, answer->type);
    ASSERT_EQ(out->flags, answer->flags);
    ASSERT_EQ(out->reserved, answer->reserved);
    ASSERT_EQ(out->stream_id, answer->stream_id);

    switch (answer->type) {
        case DATA:
            test_desrlz_dataframe(out, answer);
            break;
        case HEADERS:
            test_desrlz_headersframe(out, answer);
            break;
        case PRIORITY_TYPE:
            test_desrlz_priorityframe(out, answer);
            break;
        case RST_STREAM:
            test_desrlz_rst_streamframe(out, answer);
            break;
        case SETTINGS:
            test_desrlz_settingsframe(out, answer);
            break;
        case PUSH_PROMISE:
            test_desrlz_pushpromiseframe(out, answer);
            break;
        case PING:
            test_desrlz_pingframe(out, answer);
            break;
        case GOAWAY:
            test_desrlz_goaway(out, answer);
            break;
        case WINDOW_UPDATE:
            test_desrlz_window_updateframe(out, answer);
            break;
        case CONTINUATION:
            test_desrlz_continuation(out, answer);
            break;
        default:
            GTEST_FAIL();
    }
}

/**
 * Common body for testing deserialization functions
 */
void test_desrlz_common(char* in, uint32_t insz, Frame* answer) {
    membuf sbuf(in, in + insz);
    std::istream strm(&sbuf);

    hpack::HPacker hpe;
    Frame *out = Deserializer::deserialize_frame(strm, &hpe);
    frame_eq(out, answer);

    delete out;
    delete answer;
}

