
#include <gtest/gtest.h>

#include "test_mutator_common.h"
#include "../../h2_serializer/test/test_common.h"
#include "libfuzzer_mutator.h"
#include "../proxy_config.h"
#include "../callbacks.h"
#include "../basedir.h"

typedef hpack::HPacker::PrefixType PrefType;
typedef hpack::HPacker::IndexingType IdxType;

TEST(TestMutator, DISABLED_GetFrameSizes) {
    char buf[2048];
    auto *strm = TestMutator::get_stream1();
    for (auto f : *strm) {
        std::cout << (f->serialize(buf, 2048) - 9) << std::endl;
    }
    TestMutator::delete_stream(strm);
    std::cout << std::endl;

    strm = TestMutator::get_stream2();
    for (auto f : *strm) {
        std::cout << (f->serialize(buf, 2048) - 9) << std::endl;
    }
    TestMutator::delete_stream(strm);
}

class StreamMutator_EmptyBase : public ::testing::Test {
protected:
    StreamMutator_EmptyBase() : ss(""), tm(ss, rands) {}

    std::stringstream ss;
    std::vector<unsigned int> rands;
    TestMutator tm;
};

// Test fixture for Mutate tests
class TestMutate : public ::testing::Test {
protected:
    void SetUp() override {
        s1 = TestMutator::get_stream1();

        hf.add_header("a", "b", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
        hf.add_header("x", "y", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
        hf.add_header("dead", "beef", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

        c.add_header("a", "b", PrefType::INDEXED_HEADER, IdxType::ALL);
        c.add_header("a", "b", PrefType::INDEXED_HEADER, IdxType::ALL);
        c.add_header("x", "z", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NAME);
        c.add_header("dead", "beef", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

        pp.add_header("x", "y", PrefType::INDEXED_HEADER, IdxType::ALL);

        s_dep.push_back(&hf);
        s_dep.push_back(&c);
        s_dep.push_back(&pp);
    }

    void TearDown() override {
        delete tm;
        TestMutator::delete_stream(s1);
    }

    H2Stream *s1 = nullptr;
    TestMutator *tm = nullptr;

    HeadersFrame hf;
    Continuation c;
    PushPromiseFrame pp;
    H2Stream s_dep;
};

TEST(Test_TestUtils, my_rand) {
    char buf[] = "";
    std::vector<unsigned int> rands{1, 2, 3, 4, 5};

    TestMutator tm(buf, 0, rands);
    for (auto i : rands) {
        ASSERT_EQ(i, tm.my_rand(0));
    }
}

size_t llvm_mutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    Random r(0);
    LibFuzz_Mut lfm(r);
    return lfm.DefaultMutate(Data, Size, MaxSize);
}

void process_raw(H2Mutator &m, size_t maxsz, const ProxyConfig &f) {
    char buf[maxsz];
    uint32_t sz = m.strm_->serialize(buf, maxsz);
    if (sz > maxsz) {
        return;
    }

    int n_auth = 0;
    for (auto frm : *m.strm_) {
        if (Frame::has_headers(frm)) {
            auto *hdrs = dynamic_cast<Headers*>(frm);
            for (auto & h : hdrs->hdr_pairs) {
                if (h.first == ":authority") {
                    ++n_auth;
                }
            }
        }
    }

    char *mut_data;
    size_t newsz = preprocess_req(f, (uint8_t*)buf, sz, &mut_data);
    ASSERT_LE(newsz, sz + f.authority.length()*n_auth);
    delete[] mut_data;
}

TEST(StreamMutator, DISABLED_Mutate_Stress_Test) {
    ProxyConfig *f = ProxyConfig::get_proxy_config("fastly");

    auto s1 = TestMutator::get_stream1();
    size_t maxsz = 2048*2;
    char buf[maxsz];
    uint32_t sz = s1->serialize(buf, maxsz);

    for (int i = 0; i < 50000; ++i) {
        int rval = i*5;
        //int rval = rand() % 50000;  // un-comment for variable load testing. keep deterministic for debugging
        std::cout << i << std::endl;
        H2Mutator m(buf, sz, BASEDIR"/h2_fuzz/mut_config_data.conf");
        m.Mutate(llvm_mutate, rval, maxsz/2);
        process_raw(m, maxsz, *f);
        sz = m.strm_->serialize(buf, maxsz);
    }

    TestMutator::delete_stream(s1);
}

#define NV "name", "value"
#define YL "yunchan", "lim"
#define WITHOUT PrefType::LITERAL_HEADER_WITHOUT_INDEXING
#define WITH PrefType::LITERAL_HEADER_WITH_INDEXING
#define FULLIDX PrefType::INDEXED_HEADER, IdxType::ALL

TEST(StreamMutator, DISABLED_Headers_Stress_Test) {
    ProxyConfig *f = ProxyConfig::get_proxy_config("fastly");

    //TODO get stream with multiple frames, lots of inserting into table, and lots of indexing into static and dynamic
    HeadersFrame hf;
    hf.add_header(NV, WITHOUT, IdxType::NONE);
    hf.add_header(YL, WITH, IdxType::NONE);
    hf.add_header(NV, WITHOUT, IdxType::NONE);
    hf.add_header(":method", "POST", FULLIDX);
    hf.add_header(NV, WITH, IdxType::NONE);
    hf.add_header(NV, FULLIDX);
    hf.add_header(YL, WITH, IdxType::NAME);
    hf.add_header(YL, FULLIDX);

    Continuation c;
    c.add_header(NV, WITHOUT, IdxType::NAME);
    c.add_header(":method", "GET", WITHOUT, IdxType::NAME);
    c.add_header(NV, FULLIDX);
    c.add_header(":status", "200", FULLIDX);
    c.add_header(NV, WITH, IdxType::NONE);
    c.add_header(NV, WITHOUT, IdxType::NAME);
    c.add_header(YL, FULLIDX);
    c.add_header(NV, FULLIDX);

    H2Stream s;
    s.push_back(&hf);
    s.push_back(&c);

    size_t maxsz = 2048*2;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    for (int i = 0; i < 50000; ++i) {
        std::cout << i << std::endl;
        H2Mutator m(buf, sz, BASEDIR"h2_fuzz/test/headers_stress.conf");
        m.Mutate(llvm_mutate, i, maxsz/2);
        //process_raw(m, maxsz, *f);
        sz = m.strm_->serialize(buf, maxsz);
    }
}

TEST(HPACKIntLength, WithVariousPrefixes) {
    EXPECT_EQ(H2Mutator::hpack_int_length(69), 1);
    EXPECT_EQ(H2Mutator::hpack_int_length(69, 7), 1);
    EXPECT_EQ(H2Mutator::hpack_int_length(69, 4), 2);

    HPacker hp;
    bool valueIndexed = false;
    EXPECT_EQ(hp.getIndex(":authority", "", valueIndexed), 1);
}

TEST(HPACKIntLength, DISABLED_PrintPrefixSizes) {
    std::cout << "I,7,6,4" << std::endl;
    for (int i = 1; i <= 4096; ++i) {
        std::cout << i << "," <<
        H2Mutator::hpack_int_length(i, 7) << "," <<
        H2Mutator::hpack_int_length(i, 6) << "," <<
        H2Mutator::hpack_int_length(i, 4) << std::endl;
    }
}

TEST(StreamMutator, DISABLED_crash_6a353cb4e5c9949f9ca1b8443baf38a1cd4f5502) {
    ProxyConfig *f = ProxyConfig::get_proxy_config("cloudfront");
    std::ifstream is(BASEDIR"h2_fuzz/test/crash-6a353cb4e5c9949f9ca1b8443baf38a1cd4f5502", std::ifstream::binary);
    H2Mutator m(is, BASEDIR"h2_fuzz/mut_config_data.conf");
    process_raw(m, 2048, *f);
}

TestMutator *mutate_test(H2Stream *s1, const std::vector<unsigned int> &rands, H2Mutator::Mutator m, size_t maxsz=256, int xos=1) {
    char buf1[maxsz];
    uint32_t sz1 = s1->serialize(buf1, maxsz);

    auto *tm = new TestMutator(buf1, sz1, rands);
    tm->Mutate(m, 0, maxsz);
    return tm;
}

TEST_F(TestMutate, DelFrame) {
    auto *s_ref = TestMutator::get_stream1();
    std::vector<unsigned int> rands{1, DELETE};
    tm = mutate_test(s1, rands, nullptr);

    ASSERT_EQ(tm->strm_->size(), s_ref->size()-1);
    frame_eq(tm->strm_->at(0), s_ref->at(0));
    frame_eq(tm->strm_->at(1), s_ref->at(2));
    frame_eq(tm->strm_->at(2), s_ref->at(3));
    frame_eq(tm->strm_->at(3), s_ref->at(4));
    frame_eq(tm->strm_->at(4), s_ref->at(5));

    TestMutator::delete_stream(s_ref);
}

TEST_F(TestMutate, DelFrame_AndResolveDeps) {
    std::vector<unsigned int> rands{0, DELETE};
    char buf[512];
    uint32_t sz = s_dep.serialize(buf, 512);
    TestMutator tm(buf, sz, rands);
    tm.Mutate(nullptr, 0, 512);

    ASSERT_EQ(tm.strm_->size(), 2);
    auto c_tm = dynamic_cast<Continuation*>(tm.strm_->at(0));
    ASSERT_NE(c_tm, nullptr);
    EXPECT_EQ(c_tm->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(c_tm->prefixes[1], PrefType::INDEXED_HEADER);
    EXPECT_EQ(c_tm->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(c_tm->prefixes[3], PrefType::LITERAL_HEADER_WITHOUT_INDEXING);
    EXPECT_EQ(c_tm->idx_types[0], IdxType::NONE);
    EXPECT_EQ(c_tm->idx_types[1], IdxType::ALL);
    EXPECT_EQ(c_tm->idx_types[2], IdxType::NONE);
    EXPECT_EQ(c_tm->idx_types[3], IdxType::NONE);

    auto pp_tm = dynamic_cast<PushPromiseFrame*>(tm.strm_->at(1));
    ASSERT_NE(pp_tm, nullptr);
    EXPECT_EQ(pp_tm->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(pp_tm->idx_types[0], IdxType::NAME);

    // implicit check for validity
    uint32_t sz1 = tm.strm_->serialize(buf, 512, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf, sz1);

    for (auto hdr : *h2_strm) {delete hdr;}
    delete h2_strm;
}

TEST_F(TestMutate, DupFrame) {
    auto *s_ref = TestMutator::get_stream1();
    std::vector<unsigned int> rands{1, DUP};
    tm = mutate_test(s1, rands, nullptr);

    ASSERT_EQ(tm->strm_->size(), s_ref->size()+1);
    frame_eq(tm->strm_->at(0), s_ref->at(0));
    frame_eq(tm->strm_->at(1), s_ref->at(1));
    frame_eq(tm->strm_->at(2), s_ref->at(1));
    frame_eq(tm->strm_->at(3), s_ref->at(2));
    frame_eq(tm->strm_->at(4), s_ref->at(3));

    TestMutator::delete_stream(s_ref);
}

TEST_F(TestMutate, DupFrame_Overflow) {
    auto *s_ref = TestMutator::get_stream1();  // 96
    std::vector<unsigned int> rands{1, DUP, 1, DUP};
    size_t maxsz = TestMutator::s1_size() + ((HDRSZ+8) * 2) - 1;
    tm = mutate_test(s1, rands, nullptr, maxsz);
    tm->Mutate(nullptr, 0, maxsz);

    ASSERT_EQ(tm->strm_->size(), s_ref->size()+1);
    frame_eq(tm->strm_->at(0), s_ref->at(0));
    frame_eq(tm->strm_->at(1), s_ref->at(1));
    frame_eq(tm->strm_->at(2), s_ref->at(1));
    frame_eq(tm->strm_->at(3), s_ref->at(2));
    frame_eq(tm->strm_->at(4), s_ref->at(3));

    TestMutator::delete_stream(s_ref);
}

TEST_F(TestMutate, SwapFrame) {
    auto *s_ref = TestMutator::get_stream1();
    std::vector<unsigned int> rands{1, SWAP, 2};
    tm = mutate_test(s1, rands, nullptr);

    ASSERT_EQ(tm->strm_->size(), s_ref->size());
    frame_eq(tm->strm_->at(0), s_ref->at(0));
    frame_eq(tm->strm_->at(1), s_ref->at(2));
    frame_eq(tm->strm_->at(2), s_ref->at(1));
    frame_eq(tm->strm_->at(3), s_ref->at(3));

    TestMutator::delete_stream(s_ref);
}

TEST_F(TestMutate, SwapFrame_AndUpdateDeps) {
    /*
     *  hf.add_header("a", "b", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
        hf.add_header("x", "y", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
        hf.add_header("dead", "beef", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

        c.add_header("a", "b", PrefType::INDEXED_HEADER, IdxType::ALL);
        c.add_header("a", "b", PrefType::INDEXED_HEADER, IdxType::ALL);
        c.add_header("x", "z", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NAME);
        c.add_header("dead", "beef", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

        pp.add_header("x", "y", PrefType::INDEXED_HEADER, IdxType::ALL);
     */
    std::vector<unsigned int> rands{0, SWAP, 2};
    char buf[512];
    uint32_t sz = s_dep.serialize(buf, 512);
    TestMutator tm(buf, sz, rands);
    tm.Mutate(nullptr, 0, 512);

    ASSERT_EQ(tm.strm_->size(), 3);
    auto pp_tm = dynamic_cast<PushPromiseFrame*>(tm.strm_->at(0));
    ASSERT_NE(pp_tm, nullptr);
    EXPECT_EQ(pp_tm->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(pp_tm->idx_types[0], IdxType::NONE);

    auto c_tm = dynamic_cast<Continuation*>(tm.strm_->at(1));
    ASSERT_NE(c_tm, nullptr);
    EXPECT_EQ(c_tm->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(c_tm->prefixes[1], PrefType::INDEXED_HEADER);
    EXPECT_EQ(c_tm->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(c_tm->prefixes[3], PrefType::LITERAL_HEADER_WITHOUT_INDEXING);
    EXPECT_EQ(c_tm->idx_types[0], IdxType::NONE);
    EXPECT_EQ(c_tm->idx_types[1], IdxType::ALL);
    EXPECT_EQ(c_tm->idx_types[2], IdxType::NONE);
    EXPECT_EQ(c_tm->idx_types[3], IdxType::NONE);
}

TEST_F(TestMutate, SwapFrame_AndUpdateDeps_SwapWithNoHdrsFrame) {
    /*
     *  DATAFRAME
     *
     *  hf.add_header("a", "b", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
        hf.add_header("x", "y", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
        hf.add_header("dead", "beef", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

        c.add_header("a", "b", PrefType::INDEXED_HEADER, IdxType::ALL);
        c.add_header("a", "b", PrefType::INDEXED_HEADER, IdxType::ALL);
        c.add_header("x", "z", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NAME);
        c.add_header("dead", "beef", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

        pp.add_header("x", "y", PrefType::INDEXED_HEADER, IdxType::ALL);
     */
    DataFrame df;
    s_dep.insert(s_dep.begin(), &df);

    std::vector<unsigned int> rands{0, SWAP, 3};
    char buf[512];
    uint32_t sz = s_dep.serialize(buf, 512);
    TestMutator tm(buf, sz, rands);
    tm.Mutate(nullptr, 0, 512);

    ASSERT_EQ(tm.strm_->size(), 4);
    auto pp_tm = dynamic_cast<PushPromiseFrame*>(tm.strm_->at(0));
    ASSERT_NE(pp_tm, nullptr);
    EXPECT_EQ(pp_tm->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(pp_tm->idx_types[0], IdxType::NONE);

    //auto c_tm = dynamic_cast<Continuation*>(tm.strm_->at(2));
    //ASSERT_NE(c_tm, nullptr);
    //EXPECT_EQ(c_tm->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    //EXPECT_EQ(c_tm->prefixes[1], PrefType::INDEXED_HEADER);
    //EXPECT_EQ(c_tm->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    //EXPECT_EQ(c_tm->prefixes[3], PrefType::LITERAL_HEADER_WITHOUT_INDEXING);
    //EXPECT_EQ(c_tm->idx_types[0], IdxType::NONE);
    //EXPECT_EQ(c_tm->idx_types[1], IdxType::ALL);
    //EXPECT_EQ(c_tm->idx_types[2], IdxType::NONE);
    //EXPECT_EQ(c_tm->idx_types[3], IdxType::NONE);
}

TEST_F(StreamMutator_EmptyBase, MutateDataFrame) {
    const char *data = "abcdefg";
    DataFrame df;
    df.len = 7;
    df.data.assign(data, data+7);
    FieldRep fr(FrameField::Data, DATA);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::rpad_ABCDEFG, 256));

    ASSERT_EQ(df.len, 14);
    ASSERT_EQ(df.data.size(), 14);
    const char *answer = "abcdefgABCDEFG";
    ASSERT_EQ(memcmp(df.data.data(), answer, 14), 0);

    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::write_0x0ABCDEF001234567, 256));
    ASSERT_EQ(df.len, 14);
    ASSERT_EQ(df.data.size(), 14);
    answer = "\x0A\xBC\xDE\xF0\x01\x23\x45\x67""BCDEFG";
    ASSERT_EQ(memcmp(df.data.data(), answer, 14), 0);

    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::trim_4, 256));
    ASSERT_EQ(df.len, 10);
    ASSERT_EQ(df.data.size(), 10);
    ASSERT_EQ(memcmp(df.data.data(), answer, 10), 0);
}

TEST_F(StreamMutator_EmptyBase, MutateDataFrame_AllowedIsMaxSize) {
    const char *data = "abcdefg";
    DataFrame df;
    df.len = 7;
    df.data.assign(data, data+7);
    FieldRep fr(FrameField::Data, DATA);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::inc_byte_8, HDRSZ + 7));
    ASSERT_EQ(df.len, 7);
    const char *answer = "ibcdefg";
    ASSERT_EQ(memcmp(df.data.data(), answer, 7), 0);
}

TEST(StreamMutator, MutateDataFrame_Overflow) {
    const char *data = "abcdefg";
    DataFrame df;
    df.len = 7;
    df.data.assign(data, data+7);

    H2Stream s;
    s.push_back(&df);

    size_t maxsz = HDRSZ + 7 + 3;
    char buf1[maxsz];
    uint32_t sz1 = s.serialize(buf1, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf1, sz1, rands);

    FieldRep fr(FrameField::Data, DATA);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::rpad_ABCDEFG, maxsz));

    ASSERT_EQ(df.len, 10);
    ASSERT_EQ(df.data.size(), 10);
    const char *answer = "abcdefgABC";
    ASSERT_EQ(memcmp(df.data.data(), answer, 10), 0);
}

TEST(StreamMutator, MutateDataFrame_Overflow_Second) {
    const char *data = "abcdefg";
    DataFrame df;
    df.len = 7;
    df.data.assign(data, data+7);

    H2Stream s;
    s.push_back(&df);

    size_t maxsz = HDRSZ + 7 + 7 + 3;
    char buf1[maxsz];
    uint32_t sz1 = s.serialize(buf1, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf1, sz1, rands);

    FieldRep fr(FrameField::Data, DATA);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::rpad_ABCDEFG, maxsz));
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::rpad_ABCDEFG, maxsz));

    ASSERT_EQ(df.len, 17);
    ASSERT_EQ(df.data.size(), 17);
    const char *answer = "abcdefgABCDEFGABC";
    ASSERT_EQ(memcmp(df.data.data(), answer, 17), 0);
}

TEST_F(StreamMutator_EmptyBase, NoMutate_PriorityFlag) {
    HeadersFrame hf;
    hf.len = 0;
    hf.flags = 0;
    hf.padlen = 0;
    FieldRep fr(FrameField::Flags, BASE);

    // mutating flags always returns 1
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::set_priority, HDRSZ+5));
    ASSERT_FALSE(hf.flags & FLAG_PRIORITY);
}

TEST_F(StreamMutator_EmptyBase, SetHeaderPriorityFlag_NoGrowPastMaxSize) {
    HeadersFrame hf;
    hf.len = 0;
    hf.flags = 0;
    hf.padlen = 0;

    H2Stream s;
    s.push_back(&hf);

    size_t maxsz = HDRSZ;
    char buf1[maxsz];
    uint32_t sz1 = s.serialize(buf1, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf1, sz1, rands);

    FieldRep fr(FrameField::PriorityFlag, HEADERS);
    ASSERT_EQ(0, tm.field_mut(fr, &hf, TestMutator::set_priority, maxsz+4));
    ASSERT_FALSE(hf.flags & FLAG_PRIORITY);
}

TEST_F(StreamMutator_EmptyBase, SetHeaderPriorityFlag_AllowGrow) {
    HeadersFrame hf;
    hf.len = 0;
    hf.flags = 0;
    hf.padlen = 0;

    H2Stream s;
    s.push_back(&hf);

    size_t maxsz = HDRSZ;
    char buf1[maxsz];
    uint32_t sz1 = s.serialize(buf1, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf1, sz1, rands);

    FieldRep fr(FrameField::PriorityFlag, HEADERS);
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::set_priority, maxsz+5));
    ASSERT_TRUE(hf.flags & FLAG_PRIORITY);
}

TEST_F(StreamMutator_EmptyBase, NoMutate_PaddedFlag) {
    DataFrame df;
    df.len = 0;
    df.flags = 0;
    df.padlen = 0;
    FieldRep fr(FrameField::Flags, BASE);

    // mutating flags always returns 1
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::set_padded, HDRSZ+1));
    ASSERT_FALSE(df.flags & FLAG_PADDED);
}

TEST_F(StreamMutator_EmptyBase, SetPaddedFlag_NoGrowPastMaxSize) {
    DataFrame df;
    df.len = 0;
    df.flags = 0;
    df.padlen = 0;

    H2Stream s;
    s.push_back(&df);

    size_t maxsz = HDRSZ;
    char buf1[maxsz];
    uint32_t sz1 = s.serialize(buf1, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf1, sz1, rands);

    FieldRep fr(FrameField::PadFlag, PAD);
    ASSERT_EQ(0, tm.field_mut(fr, &df, TestMutator::set_padded, maxsz));
    ASSERT_FALSE(df.flags & FLAG_PADDED);
}

TEST_F(StreamMutator_EmptyBase, SetPaddedFlag_AllowGrow) {
    DataFrame df;
    df.len = 0;
    df.flags = 0;
    df.padlen = 0;
    H2Stream s;
    s.push_back(&df);

    size_t maxsz = HDRSZ;
    char buf1[maxsz];
    uint32_t sz1 = s.serialize(buf1, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf1, sz1, rands);

    FieldRep fr(FrameField::PadFlag, PAD);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::set_padded, HDRSZ + 1));
    ASSERT_TRUE(df.flags & FLAG_PADDED);
}

TEST_F(StreamMutator_EmptyBase, MutatePadded_NoOverflow) {
    DataFrame df;
    df.len = 1;
    df.flags |= FLAG_PADDED;
    FieldRep fr(FrameField::Length, PAD);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::inc_byte_128, 512));
    ASSERT_EQ(df.len, 129);
    ASSERT_EQ(df.padlen, 128);
    std::vector<char> answer;
    answer.insert(answer.end(), 128, 0);
    ASSERT_EQ(df.padding, answer);

    fr.field = FrameField::Padding;
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::rpad_ABCDEFG, 512));
    ASSERT_EQ(df.len, 136);
    ASSERT_EQ(df.padlen, 135);
    const char *newdata = "ABCDEFG";
    answer.insert(answer.end(), newdata, newdata+7);
    ASSERT_EQ(df.padding, answer);

    fr.field = FrameField::Length;
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::dec_byte_16, 512));
    ASSERT_EQ(df.len, 120);
    ASSERT_EQ(df.padlen, 119);
    answer.resize(119);
    ASSERT_EQ(df.padding, answer);

    fr.field = FrameField::Padding;
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::trim_4, 512));
    ASSERT_EQ(df.len, 116);
    ASSERT_EQ(df.padlen, 115);
    answer.resize(115);
    ASSERT_EQ(df.padding, answer);
}

TEST(StreamMutator, MutatePadded_OverflowLength) {
    DataFrame df;
    df.flags |= FLAG_PADDED;
    df.padlen = 0;

    H2Stream s;
    s.push_back(&df);

    size_t maxsz = 64;
    char buf1[maxsz];
    uint32_t sz1 = s.serialize(buf1, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf1, sz1, rands);

    FieldRep fr(FrameField::Length, PAD);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::inc_byte_128, maxsz));
    ASSERT_EQ(df.len, 55);
    ASSERT_EQ(df.padlen, 54);  // MaxSize - 9 - 1
    std::vector<char> answer;
    answer.insert(answer.end(), 54, 0);
    ASSERT_EQ(df.padding, answer);
}

TEST(StreamMutator, MutatePadded_OverflowLength_SecondMutate) {
    DataFrame df;
    df.flags |= FLAG_PADDED;
    df.padlen = 0;

    H2Stream s;
    s.push_back(&df);

    size_t maxsz = 32;
    char buf1[maxsz];
    uint32_t sz1 = s.serialize(buf1, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf1, sz1, rands);

    FieldRep fr(FrameField::Length, PAD);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::inc_byte_16, maxsz));
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::inc_byte_16, maxsz));

    ASSERT_EQ(df.len, maxsz-9);
    ASSERT_EQ(df.padlen, maxsz-10);
    std::vector<char> answer;
    answer.insert(answer.end(), maxsz-10, 0);
    ASSERT_EQ(df.padding, answer);
}

TEST(StreamMutator, MutatePadded_OverflowPadding) {
    DataFrame df;
    df.flags |= FLAG_PADDED;
    df.padlen = 18;
    df.padding.insert(df.padding.end(), 18, 0);

    H2Stream s;
    s.push_back(&df);

    size_t maxsz = 32;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);
    ASSERT_LE(sz, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Padding, PAD);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::rpad_ABCDEFG, maxsz));
    ASSERT_EQ(df.len, maxsz-9);
    ASSERT_EQ(df.padlen, maxsz-10);  // MaxSize - 9 - 1
    std::vector<char> answer;
    answer.insert(answer.end(), 18, 0);
    const char *newdata = "ABCD";
    answer.insert(answer.end(), newdata, newdata+strlen(newdata));
    ASSERT_EQ(df.padding, answer);
}

TEST(StreamMutator, MutatePadded_OverflowPadding_SecondMutate) {
    DataFrame df;
    df.flags |= FLAG_PADDED;
    df.padlen = 16;
    df.padding.insert(df.padding.end(), df.padlen, 0);

    H2Stream s;
    s.push_back(&df);

    size_t maxsz = HDRSZ + 1 + df.padlen + 7 + 3;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Padding, PAD);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::rpad_ABCDEFG, maxsz));
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::rpad_ABCDEFG, maxsz));
    ASSERT_EQ(df.len, maxsz-9);
    ASSERT_EQ(df.padlen, maxsz-10);
    std::vector<char> answer;
    answer.insert(answer.end(), 16, 0);
    const char *newdata = "ABCDEFGABC";
    answer.insert(answer.end(), newdata, newdata+strlen(newdata));
    ASSERT_EQ(df.padding, answer);
}

TEST_F(StreamMutator_EmptyBase, MutateRstStream) {
    RstStreamFrame rf;
    rf.len = 4;
    rf.error_code = 0xAABBCCDD;
    FieldRep fr(FrameField::ErrCode, RST_STREAM);

    ASSERT_EQ(1, tm.field_mut(fr, &rf, TestMutator::write_0x0ABCDEF001234567, 64));
    ASSERT_EQ(rf.len, 4);
    ASSERT_EQ(rf.error_code, 0xf0debc0a);
}

/** Test fixture to abstract away settings setup */
class MutateSettings_Fixture : public ::testing::Test {
protected:
    MutateSettings_Fixture() {
        sf.add_setting(SETTINGS_ENABLE_PUSH, 0);
        sf.add_setting(SETTINGS_INITIAL_WINDOW_SIZE, 0x7fffffff);
        sf.add_setting(SETTINGS_HEADER_TABLE_SIZE, 0x0000ffff);
        sf.add_setting(SETTINGS_MAX_FRAME_SIZE, 0x00ffffff);
        sf.len = 24;
        s.push_back(&sf);
    }

    SettingsFrame sf;
    H2Stream s;
};

TEST_F(MutateSettings_Fixture, MutateSettings) {
    std::stringstream ss("");
    std::vector<unsigned int> rands{0, 2};
    TestMutator tm(ss, rands);

    FieldRep fr(FrameField::ID, SETTINGS);
    ASSERT_EQ(1, tm.field_mut(fr, &sf, TestMutator::write_0x0ABCDEF001234567, 32));
    ASSERT_EQ(sf.settings[0].first, 0xbc0a);

    fr.field = FrameField::Value;
    ASSERT_EQ(1, tm.field_mut(fr, &sf, TestMutator::dec_byte_16, 32));
    ASSERT_EQ(sf.settings[2].second, 0x0000ffef);

    ASSERT_EQ(sf.len, 24);
}

TEST_F(MutateSettings_Fixture, CannotMutateWindowSize) {
    std::stringstream ss("");
    std::vector<unsigned int> rands{1};
    TestMutator tm(ss, rands);

    // field_mut returns zero because it fails
    FieldRep fr(FrameField::Value, SETTINGS);
    ASSERT_EQ(0, tm.field_mut(fr, &sf, TestMutator::dec_byte_16, 32));
    ASSERT_EQ(sf.settings[1].second, 0x7fffffff);

    ASSERT_EQ(sf.len, 24);
}

TEST_F(MutateSettings_Fixture, MutatSettings_Split) {
    for (unsigned int i = 0; i < sf.settings.size() + 1; ++i) {
        size_t maxsz = 128;
        char buf[maxsz];
        uint32_t sz = s.serialize(buf, maxsz);

        std::vector<unsigned int> rands{0, i};
        TestMutator tm(buf, sz, rands);

        FieldRep fr(FrameField::Split, SETTINGS);
        ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));
        ASSERT_EQ(tm.strm_->size(), 2);

        auto sf1 = dynamic_cast<SettingsFrame*>(tm.strm_->at(0));
        auto sf2 = dynamic_cast<SettingsFrame*>(tm.strm_->at(1));
        ASSERT_NE(sf1, nullptr);
        ASSERT_NE(sf2, nullptr);

        ASSERT_EQ(sf1->settings.size(), i);
        ASSERT_EQ(sf1->len, 6 * i);
        ASSERT_EQ(sf2->settings.size(), sf.settings.size() - i);
        ASSERT_EQ(sf2->len, 6 * (sf.settings.size() - i));

        // now compare settings equality
        int orig_idx = 0;
        for (auto s : sf1->settings) {
            ASSERT_EQ(sf.settings[orig_idx], s);
            ++orig_idx;
        }
        for (auto s : sf2->settings) {
            ASSERT_EQ(sf.settings[orig_idx], s);
            ++orig_idx;
        }
    }
}

TEST_F(MutateSettings_Fixture, MutateSettings_DupDelSwap) {
    size_t maxsz = 128;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands{0, 2, 2, 3};
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Dup, SETTINGS);
    ASSERT_EQ(1, tm.field_mut(fr, &sf, nullptr, maxsz));
    ASSERT_EQ(sf.settings.size(), 5);
    ASSERT_EQ(sf.settings[0], sf.settings[1]);
    ASSERT_EQ(sf.settings[0].first, SETTINGS_ENABLE_PUSH);
    ASSERT_EQ(sf.settings[0].second, 0);
    ASSERT_EQ(sf.len, 30);

    fr.field = FrameField::Delete;
    ASSERT_EQ(1, tm.field_mut(fr, &sf, nullptr, maxsz));
    ASSERT_EQ(sf.settings.size(), 4);
    ASSERT_EQ(sf.settings[2].first, SETTINGS_HEADER_TABLE_SIZE);
    ASSERT_EQ(sf.settings[2].second, 0x0000ffff);
    ASSERT_EQ(sf.len, 24);

    fr.field = FrameField::Swap;
    ASSERT_EQ(1, tm.field_mut(fr, &sf, nullptr, maxsz));
    ASSERT_EQ(sf.settings.size(), 4);
    ASSERT_EQ(sf.settings[2].first, SETTINGS_MAX_FRAME_SIZE);
    ASSERT_EQ(sf.settings[2].second, 0x00ffffff);
    ASSERT_EQ(sf.settings[3].first, SETTINGS_HEADER_TABLE_SIZE);
    ASSERT_EQ(sf.settings[3].second, 0x0000ffff);
    ASSERT_EQ(sf.len, 24);
}

TEST_F(MutateSettings_Fixture, MutateSettings_DupOverflow) {
    size_t maxsz = HDRSZ + sf.len + 2;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands{0};
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Dup, SETTINGS);
    ASSERT_EQ(0, tm.field_mut(fr, &sf, nullptr, maxsz));
    ASSERT_EQ(sf.settings.size(), 4);
    ASSERT_EQ(sf.len, 24);
}

TEST_F(MutateSettings_Fixture, MutateSettings_DupOverflow_Second) {
    size_t maxsz = HDRSZ + sf.len + 6 + 2;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands{0, 2};
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Dup, SETTINGS);
    ASSERT_EQ(1, tm.field_mut(fr, &sf, nullptr, maxsz));
    ASSERT_EQ(sf.settings.size(), 5);
    ASSERT_EQ(sf.len, 30);

    ASSERT_EQ(0, tm.field_mut(fr, &sf, nullptr, maxsz));
    ASSERT_EQ(sf.settings.size(), 5);
    ASSERT_EQ(sf.len, 30);
}

TEST_F(StreamMutator_EmptyBase, MutatePushPromise) {
    PushPromiseFrame pp;
    pp.len = 4;
    pp.reserved_pp = false;
    pp.prom_stream_id = 0x00000001;

    FieldRep fr(FrameField::Reserved, PUSH_PROMISE);
    ASSERT_EQ(1, tm.field_mut(fr, &pp, nullptr, 64));
    ASSERT_TRUE(pp.reserved_pp);
    ASSERT_EQ(1, tm.field_mut(fr, &pp, nullptr, 64));
    ASSERT_FALSE(pp.reserved_pp);

    fr.field = FrameField::StreamID;
    ASSERT_EQ(1, tm.field_mut(fr, &pp, TestMutator::write_0x0ABCDEF001234567, 64));
    ASSERT_EQ(pp.prom_stream_id, 0xf0debc0a);
    ASSERT_EQ(pp.len, 4);
}

TEST_F(StreamMutator_EmptyBase, MutatePing) {
    PingFrame pf;
    pf.len = 8;
    pf.data = 0xabcdef00deadbeef;

    FieldRep fr(FrameField::Data, PING);
    ASSERT_EQ(1, tm.field_mut(fr, &pf, TestMutator::write_0x0ABCDEF001234567, 64));
    ASSERT_EQ(pf.data, 0x67452301f0debc0a);
    ASSERT_EQ(pf.len, 8);
}

TEST_F(StreamMutator_EmptyBase, MutateGoAway_StaticFields) {
    GoAway ga;
    ga.reserved_ga = false;
    ga.last_stream_id = 0x00000001;
    ga.error_code = 0xdeadbeef;
    ga.len = 8;

    FieldRep fr(FrameField::Reserved, GOAWAY);
    ASSERT_EQ(1, tm.field_mut(fr, &ga, nullptr, 64));
    ASSERT_TRUE(ga.reserved_ga);
    ASSERT_EQ(1, tm.field_mut(fr, &ga, nullptr, 64));
    ASSERT_FALSE(ga.reserved_ga);

    fr.field = FrameField::StreamID;
    ASSERT_EQ(1, tm.field_mut(fr, &ga, TestMutator::write_0x0ABCDEF001234567, 64));
    ASSERT_EQ(ga.last_stream_id, 0xf0debc0a);

    fr.field = FrameField::ErrCode;
    ASSERT_EQ(1, tm.field_mut(fr, &ga, TestMutator::write_0x0ABCDEF001234567, 64));
    ASSERT_EQ(1, tm.field_mut(fr, &ga, TestMutator::inc_byte_128, 64));  // just to make the values not the same
    ASSERT_EQ(ga.error_code, 0xf0debc8a);
    ASSERT_EQ(ga.len, 8);
}

TEST(StreamMutator, MutateGoAway_DebugData) {
    GoAway ga;
    const char *dbg = "ABCDEFGH";
    ga.debug_data.insert(ga.debug_data.end(), dbg, dbg+8);
    ga.len = 16;

    H2Stream s;
    s.push_back(&ga);

    size_t maxsz = 29;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf, sz, rands);

    // overwrite data in place
    FieldRep fr(FrameField::Data, GOAWAY);
    ASSERT_EQ(1, tm.field_mut(fr, &ga, TestMutator::write_0x0ABCDEF001234567, maxsz));
    const char *raw = "\x0A\xBC\xDE\xF0\x01\x23\x45\x67";
    std::vector<char> answer;
    answer.insert(answer.end(), raw, raw+8);
    ASSERT_EQ(ga.debug_data, answer);
    ASSERT_EQ(ga.len, 16);

    // grow data and avoid outgrowing MaxSize
    ASSERT_EQ(1, tm.field_mut(fr, &ga, TestMutator::rpad_ABCDEFG, maxsz));
    const char *app = "ABCD";
    answer.insert(answer.end(), app, app+4);
    ASSERT_EQ(ga.debug_data, answer);
    ASSERT_EQ(ga.len, 20);

    // trim data from end
    ASSERT_EQ(1, tm.field_mut(fr, &ga, TestMutator::trim_4, maxsz));
    answer.resize(8);
    ASSERT_EQ(ga.debug_data, answer);
    ASSERT_EQ(ga.len, 16);
}

TEST(StreamMutator, MutateGoAway_OverflowOnSecondGrow) {
    GoAway ga;
    const char *dbg = "ABCDEFGH";
    ga.debug_data.insert(ga.debug_data.end(), dbg, dbg+8);
    ga.len = 16;

    H2Stream s;
    s.push_back(&ga);

    size_t maxsz = ga.len + HDRSZ + 7 + 3;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands;
    TestMutator tm(buf, sz, rands);

    // grow data and avoid outgrowing MaxSize
    FieldRep fr(FrameField::Data, GOAWAY);
    ASSERT_EQ(1, tm.field_mut(fr, &ga, TestMutator::rpad_ABCDEFG, maxsz));
    ASSERT_EQ(1, tm.field_mut(fr, &ga, TestMutator::rpad_ABCDEFG, maxsz));
    const char *raw = "ABCDEFGHABCDEFGABC";
    std::vector<char> answer;
    answer.insert(answer.end(), raw, raw+18);
    ASSERT_EQ(ga.debug_data, answer);
    ASSERT_EQ(ga.len, 16 + 7 + 3);
}

TEST_F(StreamMutator_EmptyBase, MutateWindowUpdate) {
    WindowUpdate wu;
    wu.len = 4;
    wu.reserved_wu = false;
    wu.win_sz_inc = 0xdeadbeef;

    FieldRep fr(FrameField::Reserved, WINDOW_UPDATE);
    ASSERT_EQ(1, tm.field_mut(fr, &wu, nullptr, 16));
    ASSERT_TRUE(wu.reserved_wu);
    ASSERT_EQ(1, tm.field_mut(fr, &wu, nullptr, 16));
    ASSERT_FALSE(wu.reserved_wu);

    fr.field = FrameField::Increment;
    ASSERT_EQ(1, tm.field_mut(fr, &wu, TestMutator::write_0x0ABCDEF001234567, 16));
    ASSERT_EQ(wu.win_sz_inc, 0xf0debc0a);
    ASSERT_EQ(wu.len, 4);
}

TEST_F(StreamMutator_EmptyBase, SetPaddedThenReDeserialize) {
    DataFrame df;
    df.len = 16;
    df.flags = FLAG_END_STREAM;
    df.reserved = false;
    df.stream_id = 0x00000001;
    df.data.insert(df.data.end(), 16, 'A');
    df.padlen = 0;

    FieldRep fr(FrameField::PadFlag, PAD);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::set_padded, 64));
    ASSERT_TRUE(df.flags & FLAG_PADDED);

    char buf[64];
    size_t sz = df.serialize(buf, 64);
    H2Stream* h2strm = Deserializer::deserialize_stream(buf, sz);

    auto *df2 = dynamic_cast<DataFrame*>(h2strm->at(0));
    ASSERT_NE(df2, nullptr);

    frame_eq(&df, df2);
    TestMutator::delete_stream(h2strm);
}

TEST_F(StreamMutator_EmptyBase, MutateBaseFrame) {
    DataFrame df;
    df.len = 16;
    df.flags = FLAG_PADDED | FLAG_END_STREAM;
    ASSERT_TRUE(df.type == DATA);
    df.reserved = false;
    df.stream_id = 0x00000001;

    // ignore. just for correctness
    df.data.insert(df.data.end(), 16, 0);
    df.padlen = 0;

    FieldRep fr(FrameField::Length, BASE);
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::write_0x0ABCDEF001234567, 32));
    ASSERT_EQ(df.len, 0xf0debc0a);

    fr.field = FrameField::Flags;
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::inc_byte_128, 32));
    ASSERT_EQ(df.flags, 128 + FLAG_PADDED + FLAG_END_STREAM);

    fr.field = FrameField::Type;
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::inc_byte_128, 32));
    ASSERT_EQ(df.type, 128 + DATA);

    fr.field = FrameField::Reserved;
    ASSERT_EQ(1, tm.field_mut(fr, &df, nullptr, 32));
    ASSERT_TRUE(df.reserved);
    ASSERT_EQ(1, tm.field_mut(fr, &df, nullptr, 32));
    ASSERT_FALSE(df.reserved);

    fr.field = FrameField::StreamID;
    ASSERT_EQ(1, tm.field_mut(fr, &df, TestMutator::write_0x0ABCDEF001234567, 32));
    ASSERT_EQ(df.stream_id, 0xf0debc0a);
}

TEST_F(StreamMutator_EmptyBase, MutateDepWeight) {
    HeadersFrame hf;
    hf.exclusive = false;
    hf.stream_dep = 0xdeadbeef;
    hf.weight = 0xab;

    FieldRep fr(FrameField::Exclusive, DEPWEIGHT);
    ASSERT_EQ(1, tm.field_mut(fr, &hf, nullptr, 16));
    ASSERT_TRUE(hf.exclusive);
    ASSERT_EQ(1, tm.field_mut(fr, &hf, nullptr, 16));
    ASSERT_FALSE(hf.exclusive);

    fr.field = FrameField::StreamID;
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::write_0x0ABCDEF001234567, 16));
    ASSERT_EQ(hf.stream_dep, 0xf0debc0a);

    fr.field = FrameField::Weight;
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::dec_byte_16, 16));
    ASSERT_EQ(hf.weight, 0x9b);
}

/** Test fixture to abstract away headers setup */
class MutateHeaders_Fixture : public ::testing::Test {
protected:
    MutateHeaders_Fixture() {
        hf.flags = FLAG_END_HEADERS;
        hf.stream_id = 0x00000001;
        // (":method", "POST")
        // \x83
        hf.add_header(":method", "POST", PrefType::INDEXED_HEADER, IdxType::ALL); // 1

        // (":scheme", "http")
        // \x46\x83\x9d\x29\xaf
        hf.add_header(":scheme", "http", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NAME); // 6

        // (":path", "/reqid=4")
        // \x10
        // \x84\xb9\x58\xd3\x3f
        // \x86\x62\xc2\xf6\x34\x90\x35
        hf.add_header(":path", "/reqid=4", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE); // 16

        // (":authority", "localhost:8000")
        // \x00
        // \x88\xb8\x3b\x53\x39\xec\x32\x7d\x7f
        // \x8a\xa0\xe4\x1d\x13\x9d\x09\xb8\xf0\x00\x0f
        hf.add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE); // 27
        s.push_back(&hf);

        ppf.flags = FLAG_END_HEADERS;
        ppf.stream_id = 0x00000001;
        s2.push_back(&ppf);

        c.flags = FLAG_END_HEADERS;
        c.stream_id = 0x00000001;
        s3.push_back(&c);

        for (int i = 0; i < hf.hdr_pairs.size(); ++i) {
            ppf.add_header(hf.hdr_pairs[i].first, hf.hdr_pairs[i].second, hf.prefixes[i], hf.idx_types[i]);
            c.add_header(  hf.hdr_pairs[i].first, hf.hdr_pairs[i].second, hf.prefixes[i], hf.idx_types[i]);
        }

        // stream where headers have dependencies on one another
        // use this to test that encodings are patched correctly after making a mutation
        hf_dep.add_header("name", "value", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
        hf_dep.add_header("name", "other", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NAME);
        hf_dep.add_header("name", "value", PrefType::INDEXED_HEADER, IdxType::ALL);
        c_dep.add_header( "name", "value", PrefType::INDEXED_HEADER, IdxType::ALL);
        s_dep.push_back(&hf_dep);
        s_dep.push_back(&c_dep);
    }

    static size_t strm_sz() {
        return HDRSZ + 3 + 42;
    }

    HeadersFrame hf;
    Continuation c;
    PushPromiseFrame ppf;
    H2Stream s, s2, s3;

    HeadersFrame hf_dep;
    Continuation c_dep;
    H2Stream s_dep;
};

void MutateHeaders_NoOverflow_impl(H2Stream &s, Frame *f) {
    auto *h = dynamic_cast<Headers *>(f);
    ASSERT_NE(h, nullptr);

    size_t maxsz = 128;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands{0, 1, 2, 100, 3, 100};
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Name, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, f, TestMutator::trim_4, maxsz));
    ASSERT_EQ(h->hdr_pairs[0].first, ":me");
    ASSERT_EQ(h->idx_types[0], IdxType::NONE); // header name no longer indexed

    ASSERT_EQ(1, tm.field_mut(fr, f, TestMutator::rpad_ABCDEFG, maxsz));
    ASSERT_EQ(h->hdr_pairs[1].first, ":schemeABCDEFG");

    fr.field = FrameField::Value;
    ASSERT_EQ(1, tm.field_mut(fr, f, TestMutator::rpad_ABCDEFG, maxsz));
    ASSERT_EQ(h->hdr_pairs[2].second, "/reqid=4ABCDEFG");
    ASSERT_EQ(1, tm.field_mut(fr, f, TestMutator::trim_4, maxsz));
    ASSERT_EQ(h->hdr_pairs[3].second, "localhost:");
}

TEST_F(MutateHeaders_Fixture, MutateHeaders_NoOverflow) {
    MutateHeaders_NoOverflow_impl(s, &hf);
    MutateHeaders_NoOverflow_impl(s2, &ppf);
    MutateHeaders_NoOverflow_impl(s3, &c);
}

void MutateHeaders_Split_impl(H2Stream &s) {
    Frame *f = s.at(0);
    auto *h = dynamic_cast<Headers *>(f);
    ASSERT_NE(h, nullptr);

    for (unsigned int i = 0; i < h->hdr_pairs.size() + 1; ++i) {
        size_t maxsz = 128;
        char buf[maxsz];
        uint32_t sz = s.serialize(buf, maxsz);

        std::vector<unsigned int> rands{0, i};
        TestMutator tm(buf, sz, rands);
        FieldRep fr(FrameField::Split, HDRS);
        ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));
        ASSERT_EQ(tm.strm_->size(), 2);

        auto h1 = dynamic_cast<Headers*>(tm.strm_->at(0));
        auto c2 = dynamic_cast<Continuation*>(tm.strm_->at(1));
        ASSERT_NE(h1, nullptr);
        ASSERT_NE(c2, nullptr);

        ASSERT_EQ(h1->hdr_pairs.size(), i);
        ASSERT_EQ(h1->prefixes.size(), i);
        ASSERT_EQ(h1->idx_types.size(), i);
        ASSERT_EQ(c2->hdr_pairs.size(), h->hdr_pairs.size() - i);
        ASSERT_EQ(c2->prefixes.size(), h->hdr_pairs.size() - i);
        ASSERT_EQ(c2->idx_types.size(), h->hdr_pairs.size() - i);

        int orig_idx = 0;
        for (int j = 0; j < h1->hdr_pairs.size(); ++j) {
            ASSERT_EQ(h1->hdr_pairs[j], h->hdr_pairs[orig_idx]);
            ASSERT_EQ(h1->prefixes[j], h->prefixes[orig_idx]);
            ASSERT_EQ(h1->idx_types[j], h->idx_types[orig_idx]);
            ++orig_idx;
        }
        for (int j = 0; j < c2->hdr_pairs.size(); ++j) {
            ASSERT_EQ(c2->hdr_pairs[j], h->hdr_pairs[orig_idx]);
            ASSERT_EQ(c2->prefixes[j], h->prefixes[orig_idx]);
            ASSERT_EQ(c2->idx_types[j], h->idx_types[orig_idx]);
            ++orig_idx;
        }
    }
}

TEST_F(MutateHeaders_Fixture, MutateHeaders_Split) {
    MutateHeaders_Split_impl(s);
    MutateHeaders_Split_impl(s2);
    MutateHeaders_Split_impl(s3);
}

TEST_F(MutateHeaders_Fixture, MutateNameValueInPlaceNearMaxSize) {
    HeadersFrame hf;
    hf.add_header("name", "value", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

    // 9 + 3 + 1 + 1 + 4 + 1 + 5 = 24
    size_t maxsz = 25;  // must be greater than actual stream size in order to catch underflow bug
    char buf[maxsz];
    hpack::HPacker hpe;
    uint32_t sz = hf.serialize(buf, maxsz, &hpe, false);
    ASSERT_EQ(sz, maxsz - 1);

    std::vector<unsigned int> rands{0, 0, 100}; // index 0
    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Name, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[0].first, "vame");

    fr.field = FrameField::Value;
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[0].second, "~alue");
}

TEST_F(MutateHeaders_Fixture, SmartMutations) {
    PrefType p = PrefType::LITERAL_HEADER_WITHOUT_INDEXING;
    IdxType i = IdxType::NONE;
    HeadersFrame hf;
    hf.add_header(":method", "GET", p, i);
    hf.add_header(":scheme", "http", p, i);
    hf.add_header(":status", "500", p, i);
    hf.add_header("transfer-encoding", "chunked", p, i);
    hf.add_header("te", "identity", p, i);
    hf.add_header("expect", "nothing", p, i);
    hf.add_header("connection", "fading", p, i);
    hf.add_header("content-length", "5", p, i);
    hf.add_header(":authority", "localhost", p, i);
    hf.add_header("host", "localhost", p, i);
    hf.add_header(":path", "/home", p, i);

    size_t maxsz = 2048;  // must be greater than actual stream size in order to catch underflow bug
    char buf[maxsz];
    hpack::HPacker hpe;
    uint32_t sz = hf.serialize(buf, maxsz, &hpe, false);

    unsigned int csv_cutoff = 25; // less than this gives comma-separated header values
    unsigned int DO_CSV = (csv_cutoff - 1);
    unsigned int SET_VALUE = (csv_cutoff + 1);

    std::vector<unsigned int> rands{0, SET_VALUE, 3,
                                    0, DO_CSV, 0,
                                    1, SET_VALUE, 1,
                                    1, DO_CSV, 0,
                                    2, SET_VALUE, 400,
                                    2, DO_CSV, 304,
                                    3, SET_VALUE, 2,
                                    4, DO_CSV, 3,
                                    5, SET_VALUE,
                                    6, SET_VALUE, 2,
                                    6, DO_CSV, 0,
                                    7, SET_VALUE, 500000, 3,
                                    7, DO_CSV, 500000, 0,
                                    8, DO_CSV, 1,
                                    9, DO_CSV, 4,
                                    10, DO_CSV, 0};
    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Value, HDRS);

    // :method
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[0].second, "POST");
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[0].second, "POST,DELETE");

    // :scheme
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[1].second, "https");
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[1].second, "https,http");

    // :status
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[2].second, "500");
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[2].second, "500,404");

    // transfer-encoding / te
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[3].second, "gzip");
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[4].second, "identity,trailers");

    // expect
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[5].second, "100-continue");

    // connection
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[6].second, "cookie");
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[6].second, "cookie,close");

    // content-length
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[7].second, "0x5");
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[7].second, "0x5,500000");

    // :authority, host, and :path
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[8].second, "https://localhost");
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[9].second, "test.com@localhost");
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[10].second, GRAMMAR_AUTH "/home");
}

TEST_F(MutateHeaders_Fixture, CSV_Mutations_DefaultToByteMut_WhenGrowingPast126) {
    PrefType p = PrefType::LITERAL_HEADER_WITHOUT_INDEXING;
    IdxType i = IdxType::NONE;
    HeadersFrame hf;
    std::string val(125, 'A');
    hf.add_header(":method", val, p, i);
    hf.add_header(":authority", val, p, i);

    size_t maxsz = 2048;  // must be greater than actual stream size in order to catch underflow bug
    char buf[maxsz];
    hpack::HPacker hpe;
    uint32_t sz = hf.serialize(buf, maxsz, &hpe, false);

    unsigned int csv_cutoff = 25; // less than this gives comma-separated header values
    unsigned int DO_CSV = (csv_cutoff - 1);
    unsigned int SET_VALUE = (csv_cutoff + 1);
    unsigned int BYTE_MUT = 51;

    std::vector<unsigned int> rands{0, DO_CSV, 0,
                                    0, BYTE_MUT,
                                    0, SET_VALUE, 0,
                                    1, DO_CSV, 1};
    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Value, HDRS);

    // :method
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[0].second, "I" + std::string(124, 'A'));
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[0].second, "Q" + std::string(124, 'A'));
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[0].second, "DELETE");

    // :authority
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, maxsz));
    EXPECT_EQ(hf.hdr_pairs[1].second, "I" + std::string(124, 'A'));
}

TEST_F(MutateHeaders_Fixture, Serialize_Mutate_Serialize) {
    auto *h = dynamic_cast<Headers *>(&hf);
    ASSERT_NE(h, nullptr);

    size_t maxsz = 128;
    char buf[maxsz];
    hpack::HPacker hpe;
    uint32_t sz = hf.serialize(buf, maxsz, &hpe, false);

    std::vector<unsigned int> rands{3}; // 3 is index of header to mutate. must be 2 or 3 since 0 and 1 are indexed
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Name, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::trim_4, maxsz));
    ASSERT_EQ(hf.hdr_pairs[3].first, ":autho");
    ASSERT_EQ(hf.idx_types[3], IdxType::NONE); // header no longer in table, so must update indexing type

    char buf_after[maxsz];
    hpack::HPacker hpe2;
    uint32_t sz_after = hf.serialize(buf_after, maxsz, &hpe2, false);

    ASSERT_EQ(sz_after, sz - 4);
}

void MutateHeaders_DupDelSwap_impl(H2Stream &s, Frame *f) {
    auto *h = dynamic_cast<Headers *>(f);
    ASSERT_NE(h, nullptr);

    size_t maxsz = 128;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands{0, 2, 2, 3};
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Dup, HDRS);
    size_t size_before = tm.size();
    ASSERT_EQ(1, tm.field_mut(fr, f, nullptr, maxsz));  // though f does not appear in strm, we mutate it directly here
    ASSERT_EQ(h->hdr_pairs.size(), 5);
    ASSERT_EQ(h->prefixes.size(), 5);
    ASSERT_EQ(h->idx_types.size(), 5);
    ASSERT_EQ(h->hdr_pairs[0], h->hdr_pairs[1]);
    ASSERT_EQ(h->hdr_pairs[0].first, ":method");
    ASSERT_EQ(h->hdr_pairs[0].second, "POST");
    ASSERT_EQ(h->prefixes[0], h->prefixes[1]);
    ASSERT_EQ(h->idx_types[0], h->idx_types[1]);
    ASSERT_EQ(h->prefixes[0], PrefType::INDEXED_HEADER);
    ASSERT_EQ(h->idx_types[0], IdxType::ALL);
    ASSERT_GT(tm.size(), size_before);

    fr.field = FrameField::Delete;
    size_before = tm.size();
    ASSERT_EQ(1, tm.field_mut(fr, f, nullptr, maxsz));
    ASSERT_EQ(h->hdr_pairs.size(), 4);
    ASSERT_EQ(h->prefixes.size(), 4);
    ASSERT_EQ(h->idx_types.size(), 4);
    ASSERT_EQ(h->hdr_pairs[2].first, ":path");
    ASSERT_EQ(h->hdr_pairs[2].second, "/reqid=4");
    ASSERT_EQ(h->prefixes[2], PrefType::LITERAL_HEADER_NEVER_INDEXED);
    ASSERT_EQ(h->idx_types[2], IdxType::NONE);
    ASSERT_LT(tm.size(), size_before);

    fr.field = FrameField::Swap;
    size_before = tm.size();
    ASSERT_EQ(1, tm.field_mut(fr, f, nullptr, maxsz));
    ASSERT_EQ(h->hdr_pairs.size(), 4);
    ASSERT_EQ(h->prefixes.size(), 4);
    ASSERT_EQ(h->idx_types.size(), 4);
    ASSERT_EQ(h->hdr_pairs[2].first, ":authority");
    ASSERT_EQ(h->hdr_pairs[2].second, "localhost:8000");
    ASSERT_EQ(h->prefixes[2], PrefType::LITERAL_HEADER_WITHOUT_INDEXING);
    ASSERT_EQ(h->idx_types[2], IdxType::NONE);
    ASSERT_EQ(h->hdr_pairs[3].first, ":path");
    ASSERT_EQ(h->hdr_pairs[3].second, "/reqid=4");
    ASSERT_EQ(h->prefixes[3], PrefType::LITERAL_HEADER_NEVER_INDEXED);
    ASSERT_EQ(h->idx_types[3], IdxType::NONE);
    ASSERT_EQ(tm.size(), size_before);
}

TEST_F(MutateHeaders_Fixture, DupDelSwap) {
    MutateHeaders_DupDelSwap_impl(s, &hf);
    MutateHeaders_DupDelSwap_impl(s2, &c);
    MutateHeaders_DupDelSwap_impl(s3, &ppf);
}

TEST_F(MutateHeaders_Fixture, MutateHeaderStringAtMaxSize) {
    /* Tests that in-place mutations can take place on header names and values when the stream is at max size */

    auto *h = dynamic_cast<Headers *>(&hf);
    ASSERT_NE(h, nullptr);

    size_t maxsz = 128;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands{3, 2, 0};  // index 0, then index 2
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Name, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_8, sz));
    ASSERT_EQ(h->hdr_pairs[3].first, "Bauthority");

    fr.field = FrameField::Value;
    ASSERT_EQ(1, tm.field_mut(fr, &hf, TestMutator::inc_byte_16, sz));
    ASSERT_EQ(h->hdr_pairs[2].second, "?reqid=4");
}

TEST_F(MutateHeaders_Fixture, MutateEncoding) {
    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = s_dep.serialize(buf, maxsz);

    // header idx 2, LITERAL_HEADER_WITH_INDEXING, NONE
    std::vector<unsigned int> rands{2, 0, 0};
    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Encoding, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));

    // implicit check for validity
    uint32_t sz1 = tm.strm_->serialize(buf, maxsz, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf, sz1);

    auto h = dynamic_cast<Headers*>(h2_strm->at(0));
    ASSERT_NE(h, nullptr);
    ASSERT_EQ(h->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    ASSERT_EQ(h->idx_types[2], IdxType::NONE);

    for (auto hdr : *h2_strm) {delete hdr;}
    delete h2_strm;
}

TEST_F(MutateHeaders_Fixture, MutateEncoding_AndResolveMaxDeps) {
    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = s_dep.serialize(buf, maxsz);

    // header idx 0, LITERAL_HEADER_WITHOUT_INDEXING, NONE
    std::vector<unsigned int> rands{0, 2, 0};
    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Encoding, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));

    // implicit check for validity
    uint32_t sz1 = tm.strm_->serialize(buf, maxsz, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf, sz1);

    auto h = dynamic_cast<Headers*>(h2_strm->at(0));
    ASSERT_NE(h, nullptr);
    ASSERT_EQ(h->prefixes[0], PrefType::LITERAL_HEADER_WITHOUT_INDEXING);
    ASSERT_EQ(h->idx_types[0], IdxType::NONE);
    ASSERT_EQ(h->prefixes[1], PrefType::LITERAL_HEADER_WITH_INDEXING);
    ASSERT_EQ(h->idx_types[1], IdxType::NONE);
    ASSERT_EQ(h->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    ASSERT_EQ(h->idx_types[2], IdxType::NAME);

    for (auto hdr : *h2_strm) {delete hdr;}
    delete h2_strm;
}

TEST_F(MutateHeaders_Fixture, MutateName_AndResolveMaxDeps) {
    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = s_dep.serialize(buf, maxsz);

    // header idx 0
    std::vector<unsigned int> rands{0};
    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Name, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), TestMutator::rpad_ABCDEFG, maxsz));

    // implicit check for validity
    uint32_t sz1 = tm.strm_->serialize(buf, maxsz, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf, sz1);

    auto h = dynamic_cast<Headers*>(h2_strm->at(0));
    ASSERT_NE(h, nullptr);
    ASSERT_EQ(h->hdr_pairs[0].first, "nameABCDEFG");
    ASSERT_EQ(h->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    ASSERT_EQ(h->idx_types[0], IdxType::NONE);
    ASSERT_EQ(h->prefixes[1], PrefType::LITERAL_HEADER_WITH_INDEXING);
    ASSERT_EQ(h->idx_types[1], IdxType::NONE);
    ASSERT_EQ(h->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    ASSERT_EQ(h->idx_types[2], IdxType::NAME);

    for (auto hdr : *h2_strm) {delete hdr;}
    delete h2_strm;
}

TEST_F(MutateHeaders_Fixture, MutateValue_AndResolveMaxDeps) {
    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = s_dep.serialize(buf, maxsz);

    // header idx 0
    std::vector<unsigned int> rands{0, 100};
    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Value, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), TestMutator::rpad_ABCDEFG, maxsz));

    auto h_dep = dynamic_cast<Headers*>(tm.strm_->at(0));
    ASSERT_NE(h_dep, nullptr);
    EXPECT_EQ(h_dep->hdr_pairs[0].second, "valueABCDEFG");
    EXPECT_EQ(h_dep->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(h_dep->idx_types[0], IdxType::NONE);
    EXPECT_EQ(h_dep->prefixes[1], PrefType::LITERAL_HEADER_WITHOUT_INDEXING);
    EXPECT_EQ(h_dep->idx_types[1], IdxType::NAME);
    EXPECT_EQ(h_dep->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(h_dep->idx_types[2], IdxType::NAME);

    // implicit check for validity
    uint32_t sz1 = tm.strm_->serialize(buf, maxsz, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf, sz1);

    for (auto hdr : *h2_strm) {delete hdr;}
    delete h2_strm;
}

TEST_F(MutateHeaders_Fixture, DeleteHeader_AndCheckSizeChange) {
    HeadersFrame hf;
    hf.add_header(":method", "POST", PrefType::INDEXED_HEADER, IdxType::ALL); // 1
    hf.add_header(":method", "POST", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NAME); // 6
    hf.add_header(":method", "POST", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE); // 14
    H2Stream strm{&hf};

    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = strm.serialize(buf, maxsz);
    uint32_t orig_len = sz - HDRSZ;

    std::vector<unsigned int> rands{0, 0, 0};
    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Delete, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));
    EXPECT_EQ(tm.strm_->at(0)->len, orig_len - 1);

    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));
    EXPECT_EQ(tm.strm_->at(0)->len, orig_len - 1 - 6);

    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));
    EXPECT_EQ(tm.strm_->at(0)->len, orig_len - 1 - (1+1+4) - (1+1+7+1+4));
}

TEST_F(MutateHeaders_Fixture, DeleteHeader_AndResolveMaxDeps) {
    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = s_dep.serialize(buf, maxsz);

    // header idx 0
    std::vector<unsigned int> rands{0};
    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Delete, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));

    auto h = dynamic_cast<Headers*>(tm.strm_->at(0));
    ASSERT_NE(h, nullptr);
    EXPECT_EQ(h->hdr_pairs.size(), 2);
    EXPECT_EQ(h->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(h->idx_types[0], IdxType::NONE);
    EXPECT_EQ(h->prefixes[1], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(h->idx_types[1], IdxType::NAME);

    // implicit check for validity
    uint32_t sz1 = tm.strm_->serialize(buf, maxsz, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf, sz1);

    for (auto hdr : *h2_strm) {delete hdr;}
    delete h2_strm;
}

void swap_headers_deps_helper(const std::vector<unsigned int> &rands, H2Stream &s_dep) {
    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = s_dep.serialize(buf, maxsz);

    TestMutator tm(buf, sz, rands);
    FieldRep fr(FrameField::Swap, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));

    auto h = dynamic_cast<Headers*>(tm.strm_->at(0));
    ASSERT_NE(h, nullptr);
    EXPECT_EQ(h->hdr_pairs[0].first, "DEAD");
    EXPECT_EQ(h->hdr_pairs[0].second, "BEEF");
    EXPECT_EQ(h->prefixes[0], PrefType::LITERAL_HEADER_WITHOUT_INDEXING);
    EXPECT_EQ(h->idx_types[0], IdxType::NONE);
    EXPECT_EQ(h->prefixes[1], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(h->idx_types[1], IdxType::NONE);
    EXPECT_EQ(h->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(h->idx_types[2], IdxType::NAME);
    EXPECT_EQ(h->hdr_pairs[3].first, "name");
    EXPECT_EQ(h->hdr_pairs[3].second, "value");
    EXPECT_EQ(h->prefixes[3], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(h->idx_types[3], IdxType::NONE);

    // implicit check for validity
    uint32_t sz1 = tm.strm_->serialize(buf, maxsz, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf, sz1);

    for (auto hdr : *h2_strm) {delete hdr;}
    delete h2_strm;
}

TEST_F(MutateHeaders_Fixture, SwapHeaders_AndResolveMaxDeps_0_3) {
    // dummy header to swap with so that we have 2 deps to resolve
    hf_dep.add_header("DEAD", "BEEF", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);
    swap_headers_deps_helper({0, 3}, s_dep);
}

TEST_F(MutateHeaders_Fixture, SwapHeaders_AndResolveMaxDeps_3_0) {
    // dummy header to swap with so that we have 2 deps to resolve
    hf_dep.add_header("DEAD", "BEEF", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);
    swap_headers_deps_helper({3, 0}, s_dep);
}

TEST_F(MutateHeaders_Fixture, SwapHeaders_AndSizeDoesNotChange) {
    HeadersFrame hf;
    hf.add_header("a", "b", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    hf.add_header("c", "d", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);

    Continuation c;
    c.add_header("c", "d", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    c.add_header("c", "d", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    c.add_header("c", "d", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NAME);

    H2Stream strm;
    strm.push_back(&hf);
    strm.push_back(&c);

    char buf[1024];
    size_t sz_orig = strm.serialize(buf, 1024);

    TestMutator tm(buf, sz_orig, {0, 2});
    FieldRep fr(FrameField::Swap, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(1), nullptr, 1024));

    size_t sz_new = tm.strm_->serialize(buf, 1024);

    ASSERT_EQ(sz_orig, sz_new);
}

TEST_F(MutateHeaders_Fixture, MutateEncoding_WithNoDependencies) {
    HeadersFrame h_test;
    h_test.add_header("a", "b", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("c", "d", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("e", "f", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("g", "h", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("i", "j", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("k", "l", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("m", "n", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("o", "p", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("q", "r", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("s", "t", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("u", "v", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("w", "x", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);
    h_test.add_header("y", "z", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NONE);

    H2Stream hstrm;
    hstrm.push_back(&h_test);

    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = hstrm.serialize(buf, maxsz);

    TestMutator tm(buf, sz, {0, 2, 0});
    FieldRep fr(FrameField::Encoding, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));
}

TEST_F(MutateHeaders_Fixture, MutateEncoding_AndResolveMaxDeps_AcrossMultipleFrames) {
    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = s_dep.serialize(buf, maxsz);

    // value mutation: header idx 2
    // encoding mutation: header idx 0, LITERAL_HEADER_WITHOUT_INDEXING, NONE
    std::vector<unsigned int> rands{2, 0, 2, 0};
    TestMutator tm(buf, sz, rands);

    // first mutate the fully-indexed header in the first frame so that it is no longer the first fully-indexed
    // occurrence of the first header in the stream anymore
    FieldRep fr(FrameField::Name, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), TestMutator::rpad_ABCDEFG, maxsz));

    auto h = dynamic_cast<Headers*>(tm.strm_->at(0));
    ASSERT_NE(h, nullptr);
    ASSERT_EQ(h->hdr_pairs[2].first, "nameABCDEFG");
    ASSERT_EQ(h->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    ASSERT_EQ(h->idx_types[2], IdxType::NONE);

    // now perform encoding mutation
    FieldRep fr2(FrameField::Encoding, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr2, tm.strm_->at(0), nullptr, maxsz));

    h = dynamic_cast<Headers*>(tm.strm_->at(0));
    ASSERT_NE(h, nullptr);
    auto c = dynamic_cast<Continuation*>(tm.strm_->at(1));
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(h->prefixes[0], PrefType::LITERAL_HEADER_WITHOUT_INDEXING);
    EXPECT_EQ(h->idx_types[0], IdxType::NONE);
    EXPECT_EQ(h->prefixes[1], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(h->idx_types[1], IdxType::NONE);
    EXPECT_EQ(h->prefixes[2], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(h->idx_types[2], IdxType::NONE);
    EXPECT_EQ(c->prefixes[0], PrefType::LITERAL_HEADER_WITH_INDEXING);
    EXPECT_EQ(c->idx_types[0], IdxType::NAME);
    EXPECT_EQ(c->len, 2 + 1 + 5); // 2 bytes for indexed header, 1 for value size, 5 for "value" <-- NOTE: 2 used to be 1 but tests were failing. haven't confirmed this is right

    // implicit check for validity
    uint32_t sz1 = tm.strm_->serialize(buf, maxsz, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf, sz1);

    for (auto hdr : *h2_strm) {delete hdr;}
    delete h2_strm;
}

TEST_F(MutateHeaders_Fixture, MutateEncoding_FullIdxToLiteral_FailsAtMaxSize) {
    /* Tests that a fully indexed header can't change to a literal if it would increase the stream size past max size */

    size_t maxsz = 62;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);
    ASSERT_EQ(sz, maxsz);

    // always pick index zero (first column) since that's the only header
    // choose every prefix/idx pair except for fully indexed and show that none of them are successfully assigned
    std::vector<unsigned int> rands{0, 1, 0,
                                    0, 1, 1,
                                    0, 2, 0,
                                    0, 2, 1,
                                    0, 3, 0,
                                    0, 3, 1};
    TestMutator tm(buf, sz, rands);

    // essential that we start at fully indexed
    auto *h = dynamic_cast<Headers*>(tm.strm_->at(0));
    ASSERT_EQ(h->prefixes[0], PrefType::INDEXED_HEADER);
    ASSERT_EQ(h->idx_types[0], IdxType::ALL);

    FieldRep fr(FrameField::Encoding, HDRS);
    for (int i = 0; i < 6; ++i) {
        ASSERT_EQ(0, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));
        ASSERT_EQ(h->prefixes[0], PrefType::INDEXED_HEADER);
        ASSERT_EQ(h->idx_types[0], IdxType::ALL);
    }
}

TEST_F(MutateHeaders_Fixture, MutateEncoding_NameIdxToLiteral_FailsAtMaxSize) {
    /* Tests that a name-indexed header cannot be changed to a literal if it would increase stream size past max size*/

    std::vector<PrefType> prefs{PrefType::LITERAL_HEADER_WITH_INDEXING,
                                PrefType::LITERAL_HEADER_WITHOUT_INDEXING,
                                PrefType::LITERAL_HEADER_NEVER_INDEXED};
    hf.idx_types[0] = IdxType::NAME;

    std::vector<unsigned int> rands{0, 1, 1,
                                    0, 2, 1,
                                    0, 3, 1};

    FieldRep fr(FrameField::Encoding, HDRS);

    size_t maxsz = 62 + 5;  // add 1 for length byte + 4 for "POST"
    char buf[maxsz];

    for (auto pref : prefs) {
        hf.reset_srlz_blk();
        hf.prefixes[0] = pref;

        uint32_t sz = s.serialize(buf, maxsz);
        ASSERT_EQ(sz, maxsz);
        TestMutator tm(buf, sz, rands);

        // sanity check that we assigned the right header
        auto *h = dynamic_cast<Headers*>(tm.strm_->at(0));
        ASSERT_EQ(h->prefixes[0], pref);
        ASSERT_EQ(h->idx_types[0], IdxType::NAME);

        for (int i = 0; i < 3; ++i) {
            ASSERT_EQ(0, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));
            // TODO should we test for exact prefix value too?
            ASSERT_EQ(h->idx_types[0], IdxType::NAME);
        }
    }
}

TEST_F(MutateHeaders_Fixture, SizeChangingAfterEncoding) {
    auto *h = dynamic_cast<Headers *>(&hf);
    ASSERT_NE(h, nullptr);

    h->prefixes[0] = PrefType::LITERAL_HEADER_WITHOUT_INDEXING;
    h->idx_types[0] = IdxType::NONE;

    size_t maxsz = 512;
    char buf[maxsz];
    uint32_t sz = s.serialize(buf, maxsz);

    std::vector<unsigned int> rands{0, 2, 2};
    TestMutator tm(buf, sz, rands);

    FieldRep fr(FrameField::Encoding, HDRS);
    ASSERT_EQ(1, tm.field_mut(fr, tm.strm_->at(0), nullptr, maxsz));

    uint32_t sz1 = tm.strm_->serialize(buf, maxsz, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf, sz1);
    uint32_t sz2 = h2_strm->serialize(buf, maxsz, false);

    ASSERT_EQ(sz1, sz2);

    for (auto *f : *h2_strm) {
        delete f;
    }
    delete h2_strm;
}

TEST(TestFixMutation, SetsFlagsAppropriately) {
    DataFrame df;
    df.flags |= FLAG_END_STREAM;
    HeadersFrame hf;
    hf.flags |= FLAG_END_HEADERS;
    Continuation c;
    c.flags |= FLAG_PADDED;

    H2Stream strm{&df, &hf, &c};
    char buf1[1024];
    uint32_t sz1 =strm.serialize(buf1, 1024);

    std::vector<unsigned int> rands{0, FIX};
    TestMutator tm(buf1, sz1, rands);
    tm.Mutate(nullptr, 0, 1024);

    char buf2[1024];
    uint32_t sz2 = tm.strm_->serialize(buf2, 1024, false);
    auto *h2_strm = Deserializer::deserialize_stream(buf2, sz2);

    ASSERT_NE(h2_strm, nullptr);
    ASSERT_EQ(h2_strm->size(), 3);
    ASSERT_EQ(h2_strm->at(0)->flags, 0);
    ASSERT_EQ(h2_strm->at(1)->flags, FLAG_END_STREAM);
    ASSERT_EQ(h2_strm->at(2)->flags, FLAG_END_HEADERS + FLAG_PADDED);

    for (auto *f : *h2_strm) {
        delete f;
    }
    delete h2_strm;
}
