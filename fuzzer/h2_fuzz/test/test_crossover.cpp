#include <gtest/gtest.h>
#include "test_mutator_common.h"
#include "../../h2_serializer/test/test_common.h"

TestMutator *cross_over_test(H2Stream *s1, H2Stream *s2, const std::vector<unsigned int> &rands,
                             size_t maxsz=512, int xos=1, const std::vector<size_t> &expected={}) {
    char buf1[maxsz];
    uint32_t sz1 = s1->serialize(buf1, maxsz);

    char buf2[maxsz];
    uint32_t sz2 = s2->serialize(buf2, maxsz);

    auto *tm = new TestMutator(buf1, sz1, rands);
    H2Mutator mut(buf2, sz2);
    for (int i = 0; i < xos; ++i) {
        if (expected.empty()) {
            EXPECT_EQ(1, tm->CrossOver(mut, 0, maxsz));
        } else {
            EXPECT_EQ(expected[i], tm->CrossOver(mut, 0, maxsz));
        }
    }
    return tm;
}

// Test fixture for CrossOver tests
class TestCrossOver : public ::testing::Test {
protected:
    void SetUp() override {
        s1 = TestMutator::get_stream1();
        s2 = TestMutator::get_stream2();

        char buf1[2048];
        uint32_t sz1 = s1->serialize(buf1, 2048);
        s3 = Deserializer::deserialize_stream(buf1, sz1);

        char buf2[2048];
        uint32_t sz2 = s2->serialize(buf2, 2048);
        s4 = Deserializer::deserialize_stream(buf2, sz2);
    }

    void TearDown() override {
        delete tm;
        TestMutator::delete_stream(s4);
        TestMutator::delete_stream(s3);
        TestMutator::delete_stream(s2);
        TestMutator::delete_stream(s1);
    }

    H2Stream *s1 = nullptr, *s2 = nullptr, *s3, *s4;
    TestMutator *tm = nullptr;
};

TEST_F(TestCrossOver, CrossOver_0_ADD_0_Frame) {
    // at index 0 of s1, add frame 0 in s2
    std::vector<unsigned int> rands{0, 0, 0, 0, ADD, 0};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz+1);
    frame_eq(tm->strm_->at(0), s2->at(0));
    frame_eq(tm->strm_->at(1), s1->at(0));
    frame_eq(tm->strm_->at(2), s1->at(1));
    frame_eq(tm->strm_->at(3), s1->at(2));
    frame_eq(tm->strm_->at(4), s1->at(3));
}

TEST_F(TestCrossOver, CrossOver_1_ADD_1_Frame) {
    // at index 1 of s1, add frame 1 in s2
    std::vector<unsigned int> rands{1, 1, 1, ADD, 1};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz+1);
    frame_eq(tm->strm_->at(0), s1->at(0));
    frame_eq(tm->strm_->at(1), s2->at(1));
    frame_eq(tm->strm_->at(2), s1->at(1));
    frame_eq(tm->strm_->at(3), s1->at(2));
    frame_eq(tm->strm_->at(4), s1->at(3));
}

TEST_F(TestCrossOver, CrossOver_0_SPLICE_0_Frame) {
    // at index 0 of s1, splice in frame 0 in s2
    std::vector<unsigned int> rands{0, 0, 0, 0, SPLICE, 0};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz);
    frame_eq(tm->strm_->at(0), s2->at(0));
    frame_eq(tm->strm_->at(1), s1->at(1));
    frame_eq(tm->strm_->at(2), s1->at(2));
    frame_eq(tm->strm_->at(3), s1->at(3));
}

TEST_F(TestCrossOver, CrossOver_0_SPLICE_0_Frame_With_Small_Stream) {
    HeadersFrame hf;
    H2Stream s_test = {&hf};

    std::vector<unsigned int> rands{0, 0, 0, 0, SPLICE, 0};
    tm = cross_over_test(&s_test, s2, rands);
}

TestMutator* crossover_withheaders_exceedsmaxsize_helper(Frame *hf, unsigned int op, size_t maxsz) {
    DataFrame df; // sz = 9
    H2Stream s_this = {&df};
    char buf1[9];
    uint32_t sz1 = s_this.serialize(buf1, 9);

    H2Stream s_other = {hf};
    char buf2[HDRSZ + hf->len];
    uint32_t sz2 = s_other.serialize(buf2, HDRSZ + hf->len);

    std::vector<unsigned int> rands{0, 0, 0, 0, op, 0};
    auto *tm = new TestMutator(buf1, sz1, rands);
    H2Mutator mut(buf2, sz2);
    EXPECT_EQ(0, tm->CrossOver(mut, 0, maxsz));

    // assert that crossover doesn't happen because of size
    EXPECT_EQ(tm->strm_->size(), 1);
    return tm;
}

TEST_F(TestCrossOver, CrossOver_HeadersFrame_WithPadding_ADD_ExceedsMaxSize) {
    HeadersFrame hf; // sz = 9 + 1 + 128 = 138
    hf.len = 129;
    hf.flags |= FLAG_PADDED;
    hf.padlen = 128;
    hf.padding.resize(hf.padlen);

    tm = crossover_withheaders_exceedsmaxsize_helper(&hf, ADD, HDRSZ + HDRSZ + hf.len - 1);
}

TEST_F(TestCrossOver, CrossOver_PushPromise_WithPadding_ADD_ExceedsMaxSize) {
    PushPromiseFrame pp; // sz = 1 + 4 + 128 = 133
    pp.len = 133;
    pp.flags |= FLAG_PADDED;
    pp.padlen = 128;
    pp.padding.resize(pp.padlen);

    tm = crossover_withheaders_exceedsmaxsize_helper(&pp, ADD, HDRSZ + HDRSZ + pp.len - 1);
}

TEST_F(TestCrossOver, CrossOver_HeadersFrame_WithDepWeight_ADD_ExceedsMaxSize) {
    HeadersFrame hf; // sz = 9 + 5 = 14
    hf.len = 5;
    hf.flags |= FLAG_PRIORITY;

    tm = crossover_withheaders_exceedsmaxsize_helper(&hf, ADD, HDRSZ + HDRSZ + hf.len - 1);
}

TEST_F(TestCrossOver, CrossOver_HeadersFrame_WithPadding_SPLICE_ExceedsMaxSize) {
    HeadersFrame hf; // sz = 9 + 1 + 128 = 138
    hf.len = 129;
    hf.flags |= FLAG_PADDED;
    hf.padlen = 128;
    hf.padding.resize(hf.padlen);

    tm = crossover_withheaders_exceedsmaxsize_helper(&hf, SPLICE, HDRSZ + HDRSZ);
}

TEST_F(TestCrossOver, CrossOver_PushPromise_WithPadding_SPLICE_ExceedsMaxSize) {
    PushPromiseFrame pp; // sz = 1 + 4 + 128 = 138
    pp.len = 133;
    pp.flags |= FLAG_PADDED;
    pp.padlen = 128;
    pp.padding.resize(pp.padlen);

    tm = crossover_withheaders_exceedsmaxsize_helper(&pp, SPLICE, HDRSZ + HDRSZ);
}

TEST_F(TestCrossOver, CrossOver_HeadersFrame_WithDepWeight_SPLICE_ExceedsMaxSize) {
    HeadersFrame hf; // sz = 9 + 5 = 14
    hf.len = 5;
    hf.flags |= FLAG_PRIORITY;

    tm = crossover_withheaders_exceedsmaxsize_helper(&hf, SPLICE, HDRSZ + HDRSZ);
}

TEST(StreamMutator, CrossOver_Frame_ADD_Overflow) {
    auto *df1 = new DataFrame();
    df1->len = 16;
    df1->data.insert(df1->data.begin(), 16, 'A');
    auto *df2 = FrameCopier::copy_frame(df1);

    auto *s1 = new H2Stream();
    s1->push_back(df1);
    auto *s2 = new H2Stream();
    s2->push_back(df2);

    std::vector<unsigned int> rands{0, 0, 0, ADD, 1};
    auto *tm = cross_over_test(s1, s2, rands, 2*(HDRSZ + df1->len) - 1, 1, {0});
    ASSERT_EQ(tm->strm_->size(), 1);

    delete tm;
    TestMutator::delete_stream(s2);
    TestMutator::delete_stream(s1);
}

TEST(StreamMutator, CrossOver_Frame_ADD_Overflow_Second) {
    auto *df1 = new DataFrame();
    df1->len = 16;
    df1->data.insert(df1->data.begin(), 16, 'A');
    auto *df2 = FrameCopier::copy_frame(df1);

    auto *s1 = new H2Stream();
    s1->push_back(df1);
    auto *s2 = new H2Stream();
    s2->push_back(df2);

    std::vector<unsigned int> rands{0, 0, 0, ADD, 1,
                                    0, 0, 0, ADD, 1};
    size_t maxsz = 3*(HDRSZ + df1->len) - 1;
    auto *tm = cross_over_test(s1, s2, rands, maxsz, 2, {1, 0});
    ASSERT_EQ(tm->strm_->size(), 2);

    delete tm;
    TestMutator::delete_stream(s2);
    TestMutator::delete_stream(s1);
}

TEST_F(TestCrossOver, CrossOver_1_SPLICE_1_Frame) {
    // at index 1 of s1, splice in frame 1 in s2
    std::vector<unsigned int> rands{1, 1, 1, SPLICE, 1};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz);
    frame_eq(tm->strm_->at(0), s1->at(0));
    frame_eq(tm->strm_->at(1), s2->at(1));
    frame_eq(tm->strm_->at(2), s1->at(2));
    frame_eq(tm->strm_->at(3), s1->at(3));
}

class CrossOver_FrameOverflow_Fixture : public ::testing::Test {
protected:
    CrossOver_FrameOverflow_Fixture() {
        df1 = new DataFrame();
        df1->len = 16;
        df1->data.insert(df1->data.begin(), 16, 'A');
        df2 = dynamic_cast<DataFrame*>(FrameCopier::copy_frame(df1));
        df3 = new DataFrame();
        df3->len = 20;
        df3->data.insert(df3->data.begin(), 20, 'B');

        s1 = new H2Stream();
        s1->push_back(df1);
        s1->push_back(df2);
        s2 = new H2Stream();
        s2->push_back(df3);
    }

    ~CrossOver_FrameOverflow_Fixture() override {
        delete tm;
        TestMutator::delete_stream(s2);
        TestMutator::delete_stream(s1);
    }

    DataFrame *df1, *df2, *df3;
    H2Stream *s1, *s2;
    TestMutator *tm = nullptr;
    std::vector<unsigned int> rands{0, 0, 0, SPLICE, 0,
                                    0, 0, 0, SPLICE, 1};
};

TEST_F(CrossOver_FrameOverflow_Fixture, CrossOver_Frame_SPLICE_Overflow) {
    tm = cross_over_test(s1, s2, rands, 2*(HDRSZ + df1->len), 1, {0});
    ASSERT_EQ(tm->strm_->size(), 2);
    ASSERT_EQ(tm->strm_->at(0)->len, 16);  // tries to write this as 20
    ASSERT_EQ(tm->strm_->at(1)->len, 16);
}

TEST_F(CrossOver_FrameOverflow_Fixture, CrossOver_Frame_SPLICE_Overflow_Second) {
    size_t maxsz = 2*(HDRSZ + df1->len) + 6;
    tm = cross_over_test(s1, s2, rands, maxsz, 2, {1, 0});
    ASSERT_EQ(tm->strm_->size(), 2);
    ASSERT_EQ(tm->strm_->at(0)->len, 20);
    ASSERT_EQ(tm->strm_->at(1)->len, 16);  // tries to write this as 20
}

void hdr_eq(HeadersFrame *hf_mut, HeadersFrame *hf_orig, int idx1, int idx2) {
    ASSERT_EQ(hf_mut->hdr_pairs[idx1], hf_orig->hdr_pairs[idx2]);
    ASSERT_EQ(hf_mut->prefixes[idx1], hf_orig->prefixes[idx2]);
    ASSERT_EQ(hf_mut->idx_types[idx1], hf_orig->idx_types[idx2]);
}

TEST_F(TestCrossOver, CrossOver_0_ADD_0_Header_0_0) {
    // insert header 0 of frame 0 to index 0 of h
    // stream 2, frame 0, header 0 -ADD-> stream 1, frame 0, header 0
    std::vector<unsigned int> rands{0, 0, 1, 0, ADD, 0};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz);
    ASSERT_EQ(tm->strm_->at(0)->type, HEADERS);
    auto hf_mut = dynamic_cast<HeadersFrame *>(tm->strm_->at(0));
    ASSERT_EQ(hf_mut->hdr_pairs.size(), 5);
    ASSERT_EQ(hf_mut->prefixes.size(), 5);
    ASSERT_EQ(hf_mut->idx_types.size(), 5);
    auto hf_orig1 = dynamic_cast<HeadersFrame *>(s3->at(0));
    auto hf_orig2 = dynamic_cast<HeadersFrame *>(s4->at(0));
    hdr_eq(hf_mut, hf_orig2, 0, 0);
    hdr_eq(hf_mut, hf_orig1, 1, 0);
    hdr_eq(hf_mut, hf_orig1, 2, 1);
    hdr_eq(hf_mut, hf_orig1, 3, 2);
    hdr_eq(hf_mut, hf_orig1, 4, 3);

    frame_eq(tm->strm_->at(1), s1->at(1));
    frame_eq(tm->strm_->at(2), s1->at(2));
    frame_eq(tm->strm_->at(3), s1->at(3));
}

TEST_F(TestCrossOver, CrossOver_0_ADD_0_Header_1_2) {
    // at index 1 of s1, add frame 0 in s2
    std::vector<unsigned int> rands{0, 0, 1, 2, ADD, 1};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz);
    ASSERT_EQ(tm->strm_->at(0)->type, HEADERS);
    auto hf_mut = dynamic_cast<HeadersFrame *>(tm->strm_->at(0));
    ASSERT_EQ(hf_mut->hdr_pairs.size(), 5);
    ASSERT_EQ(hf_mut->prefixes.size(), 5);
    ASSERT_EQ(hf_mut->idx_types.size(), 5);
    auto hf_orig1 = dynamic_cast<HeadersFrame *>(s3->at(0));
    auto hf_orig2 = dynamic_cast<HeadersFrame *>(s4->at(0));
    hdr_eq(hf_mut, hf_orig1, 0, 0);
    hdr_eq(hf_mut, hf_orig2, 1, 2);
    hdr_eq(hf_mut, hf_orig1, 2, 1);
    hdr_eq(hf_mut, hf_orig1, 3, 2);
    hdr_eq(hf_mut, hf_orig1, 4, 3);

    frame_eq(tm->strm_->at(1), s1->at(1));
    frame_eq(tm->strm_->at(2), s1->at(2));
    frame_eq(tm->strm_->at(3), s1->at(3));
}

TEST_F(TestCrossOver, CrossOver_0_SPLICE_0_Header_0_0) {
    // at index 0 of s1, splice in frame 0 in s2
    std::vector<unsigned int> rands{0, 0, 1, 0, SPLICE, 0};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz);
    ASSERT_EQ(tm->strm_->at(0)->type, HEADERS);
    auto hf_mut = dynamic_cast<HeadersFrame *>(tm->strm_->at(0));
    ASSERT_EQ(hf_mut->hdr_pairs.size(), 4);
    ASSERT_EQ(hf_mut->prefixes.size(), 4);
    ASSERT_EQ(hf_mut->idx_types.size(), 4);
    auto hf_orig1 = dynamic_cast<HeadersFrame *>(s3->at(0));
    auto hf_orig2 = dynamic_cast<HeadersFrame *>(s4->at(0));
    hdr_eq(hf_mut, hf_orig2, 0, 0);
    hdr_eq(hf_mut, hf_orig1, 1, 1);
    hdr_eq(hf_mut, hf_orig1, 2, 2);
    hdr_eq(hf_mut, hf_orig1, 3, 3);

    frame_eq(tm->strm_->at(1), s1->at(1));
    frame_eq(tm->strm_->at(2), s1->at(2));
    frame_eq(tm->strm_->at(3), s1->at(3));
}

TEST_F(TestCrossOver, CrossOver_0_SPLICE_0_Header_1_2) {
    // at index 1 of s1, splice in frame 1 in s2
    std::vector<unsigned int> rands{0, 0, 1, 2, SPLICE, 1};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz);
    ASSERT_EQ(tm->strm_->at(0)->type, HEADERS);
    auto hf_mut = dynamic_cast<HeadersFrame *>(tm->strm_->at(0));
    ASSERT_EQ(hf_mut->hdr_pairs.size(), 4);
    ASSERT_EQ(hf_mut->prefixes.size(), 4);
    ASSERT_EQ(hf_mut->idx_types.size(), 4);
    auto hf_orig1 = dynamic_cast<HeadersFrame *>(s3->at(0));
    auto hf_orig2 = dynamic_cast<HeadersFrame *>(s4->at(0));
    hdr_eq(hf_mut, hf_orig1, 0, 0);
    hdr_eq(hf_mut, hf_orig2, 1, 2);
    hdr_eq(hf_mut, hf_orig1, 2, 2);
    hdr_eq(hf_mut, hf_orig1, 3, 3);

    frame_eq(tm->strm_->at(1), s1->at(1));
    frame_eq(tm->strm_->at(2), s1->at(2));
    frame_eq(tm->strm_->at(3), s1->at(3));
}

TEST_F(TestCrossOver, CrossOver_3_ADD_3_Frame_2_1) {
    std::vector<unsigned int> rands{3, 3, 0, 1, ADD, 2};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz+1);
    frame_eq(tm->strm_->at(0), s1->at(0));
    frame_eq(tm->strm_->at(1), s1->at(1));
    frame_eq(tm->strm_->at(2), s2->at(1));
    frame_eq(tm->strm_->at(3), s1->at(2));
    frame_eq(tm->strm_->at(4), s1->at(3));
}

TEST_F(TestCrossOver, CrossOver_3_ADD_3_Settings_2_1) {
    std::vector<unsigned int> rands{3, 3, 1, 1, ADD, 2};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz);
    ASSERT_EQ(tm->strm_->at(3)->type, SETTINGS);
    ASSERT_EQ(tm->strm_->at(3)->type, SETTINGS);
    auto sf_mut = dynamic_cast<SettingsFrame *>(tm->strm_->at(3));
    ASSERT_EQ(sf_mut->settings.size(), 4);
    auto sf_orig1 = dynamic_cast<SettingsFrame *>(s1->at(3));
    auto sf_orig2 = dynamic_cast<SettingsFrame *>(s2->at(3));
    ASSERT_EQ(sf_mut->settings[0], sf_orig1->settings[0]);
    ASSERT_EQ(sf_mut->settings[1], sf_orig1->settings[1]);
    ASSERT_EQ(sf_mut->settings[2], sf_orig2->settings[1]);
    ASSERT_EQ(sf_mut->settings[3], sf_orig1->settings[2]);
}

TEST_F(TestCrossOver, CrossOver_3_SPLICE_3_Settings_1_2) {
    std::vector<unsigned int> rands{3, 3, 1, 2, SPLICE, 1};
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands);

    ASSERT_EQ(tm->strm_->size(), origsz);
    ASSERT_EQ(tm->strm_->at(3)->type, SETTINGS);
    ASSERT_EQ(tm->strm_->at(3)->type, SETTINGS);
    auto sf_mut = dynamic_cast<SettingsFrame *>(tm->strm_->at(3));
    ASSERT_EQ(sf_mut->settings.size(), 3);
    auto sf_orig1 = dynamic_cast<SettingsFrame *>(s1->at(3));
    auto sf_orig2 = dynamic_cast<SettingsFrame *>(s2->at(3));
    ASSERT_EQ(sf_mut->settings[0], sf_orig1->settings[0]);
    ASSERT_EQ(sf_mut->settings[1], sf_orig2->settings[2]);
    ASSERT_EQ(sf_mut->settings[2], sf_orig1->settings[2]);
}

TEST_F(TestCrossOver, CrossOver_Settings_Add_Overflow) {
    std::vector<unsigned int> rands{3, 3, 1, 2, ADD, 1,
                                    3, 3, 1, 2, ADD, 1};
    size_t maxsz = TestMutator::s1_size() + (2*6) - 1; // manually say sizeof Setting for no rounding
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands, maxsz, 2, {1, 0});
    ASSERT_NE(tm->strm_, nullptr);
    ASSERT_EQ(tm->strm_->size(), origsz);
    ASSERT_EQ(tm->strm_->at(3)->type, SETTINGS);
    ASSERT_EQ(tm->strm_->at(3)->type, SETTINGS);
    auto sf_mut = dynamic_cast<SettingsFrame *>(tm->strm_->at(3));
    ASSERT_EQ(sf_mut->settings.size(), 4);
}

TEST_F(TestCrossOver, CrossOver_Settings_Splice_CantOverflow) {
    std::vector<unsigned int> rands{3, 3, 1, 2, SPLICE, 1,
                                    3, 3, 1, 2, SPLICE, 1};
    size_t maxsz = TestMutator::s1_size() + 2;
    size_t origsz = s1->size();
    tm = cross_over_test(s1, s2, rands, maxsz, 2);
    ASSERT_NE(tm->strm_, nullptr);
    ASSERT_EQ(tm->strm_->size(), origsz);
    ASSERT_EQ(tm->strm_->at(3)->type, SETTINGS);
    ASSERT_EQ(tm->strm_->at(3)->type, SETTINGS);
    auto sf_mut = dynamic_cast<SettingsFrame *>(tm->strm_->at(3));
    ASSERT_EQ(sf_mut->settings.size(), 3);
}

TEST_F(TestCrossOver, CrossOver_Add_Continuation_from_PushPromise) {
    std::vector<unsigned int> rands{4, 5, 1, 0, ADD, 2};

    ASSERT_EQ(s1->at(4)->type, CONTINUATION);
    auto c_orig = dynamic_cast<Continuation *>(s1->at(4));
    ASSERT_EQ(s2->at(5)->type, PUSH_PROMISE);
    auto pp_orig = dynamic_cast<PushPromiseFrame *>(s2->at(5));

    tm = cross_over_test(s1, s2, rands);
    ASSERT_NE(tm->strm_, nullptr);
    ASSERT_EQ(tm->strm_->size(), s1->size());
    ASSERT_EQ(tm->strm_->at(4)->type, CONTINUATION);
    auto c_mut = dynamic_cast<Continuation *>(tm->strm_->at(4));
    ASSERT_EQ(c_mut->hdr_pairs.size(), c_orig->hdr_pairs.size()+1);
    ASSERT_EQ(c_mut->hdr_pairs[0], c_orig->hdr_pairs[0]);
    ASSERT_EQ(c_mut->hdr_pairs[1], c_orig->hdr_pairs[1]);
    ASSERT_EQ(c_mut->hdr_pairs[2], pp_orig->hdr_pairs[0]);
    ASSERT_EQ(c_mut->hdr_pairs[3], c_orig->hdr_pairs[2]);
    ASSERT_EQ(c_mut->hdr_pairs[4], c_orig->hdr_pairs[3]);
}

TEST_F(TestCrossOver, CrossOver_Splice_PushPromise_from_Continuation) {
    std::vector<unsigned int> rands{5, 4, 1, 1, SPLICE, 1};

    ASSERT_EQ(s2->at(4)->type, CONTINUATION);
    auto c_orig = dynamic_cast<Continuation *>(s2->at(4));
    ASSERT_EQ(s1->at(5)->type, PUSH_PROMISE);
    auto pp_orig = dynamic_cast<PushPromiseFrame *>(s1->at(5));

    tm = cross_over_test(s1, s2, rands);
    ASSERT_NE(tm->strm_, nullptr);
    ASSERT_EQ(tm->strm_->size(), s1->size());
    ASSERT_EQ(tm->strm_->at(5)->type, PUSH_PROMISE);
    auto pp_mut = dynamic_cast<PushPromiseFrame *>(tm->strm_->at(5));
    ASSERT_EQ(pp_mut->hdr_pairs.size(), pp_orig->hdr_pairs.size());
    ASSERT_EQ(pp_mut->hdr_pairs[0], pp_orig->hdr_pairs[0]);
    ASSERT_EQ(pp_mut->hdr_pairs[1], c_orig->hdr_pairs[1]);
}

TEST_F(TestCrossOver, DISABLED_CrossOver_Stress_Test) {
    size_t maxsz = 2048;
    char buf1[maxsz];
    uint32_t sz1 = s1->serialize(buf1, maxsz);

    char buf2[maxsz];
    uint32_t sz2 = s2->serialize(buf2, maxsz);

    H2Mutator m1(buf1, sz1);
    H2Mutator m2(buf2, sz2);
    int i = 0;
    while (i < 10000) {
        m1.CrossOver(m2, i++, maxsz);
        m2.CrossOver(m1, i++, maxsz);
    }
}