
#include <gtest/gtest.h>
#include "../hashcomp.h"
#include "../util.h"

void hashcomp_common(const char *req, ProxyConfig *f, HashComp *hc) {
    size_t sz = strlen(req);
    H1Parser h1p;
    h1p.parse(req, sz);
    hc->parse(h1p, *f);
}

TEST(HashComp, Parse_EmptyH1Parser) {
    H1Parser h1p;
    ProxyConfig f;
    HashComp hc;
    hc.parse(h1p, f);
    ASSERT_EQ(hc.reqline_str, nullptr);
    ASSERT_EQ(hc.host_str, nullptr);
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_EQ(hc.te_str, nullptr);
    ASSERT_EQ(hc.body_str, nullptr);

    hc.hash_indiv();
    ASSERT_EQ(hc.version_hash, 0);
    ASSERT_EQ(hc.method_hash, 0);
    ASSERT_EQ(hc.host_hash, 0);
    ASSERT_EQ(hc.cl_hash, 0);
    ASSERT_EQ(hc.te_hash, 0);
    ASSERT_EQ(hc.body_hash, 0);
    ASSERT_EQ(hc.rem_host_hash, 0);
    ASSERT_EQ(hc.rem_cl_hash, 0);
    ASSERT_EQ(hc.rem_te_hash, 0);
}

TEST(HashComp, Parse_NoHdrs_NoBody_NoFilter) {
    const char *req = "GET /home HTTP/1.1\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_EQ(hc.host_str, nullptr);
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_EQ(hc.te_str, nullptr);
    ASSERT_EQ(hc.body_str, nullptr);
}

TEST(HashComp, Parse_SimpleGet_CL_NoFilter) {
    const char *req = "GET /home HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\n\r\nABCDEFG";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_STREQ(hc.host_str->c_str(), " localhost");
    ASSERT_STREQ(hc.cl_str->c_str(), " 7");
    ASSERT_EQ(hc.te_str, nullptr);
    ASSERT_STREQ(hc.body_str->c_str(), "ABCDEFG");
}

TEST(HashComp, Parse_SimpleGet_TE_Chunked_Simple_NoFilter) {
    const char *req = "GET /home HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nABCDEFG\r\n0\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_STREQ(hc.host_str->c_str(), " localhost");
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_STREQ(hc.te_str->c_str(), " chunked");
    ASSERT_STREQ(hc.body_str->c_str(), "ABCDEFG");  // auto-parses chunked body
}

TEST(HashComp, Parse_SimpleGet_TE_Chunked_LongChunkSize_NoFilter) {
    const char *req = "GET /home HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1E\r\nAAAABBBBCCCCDDDDEEEEFFFFGGGGHH\r\n0\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_STREQ(hc.host_str->c_str(), " localhost");
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_STREQ(hc.te_str->c_str(), " chunked");
    ASSERT_STREQ(hc.body_str->c_str(), "AAAABBBBCCCCDDDDEEEEFFFFGGGGHH");  // auto-parses chunked body
}

TEST(HashComp, Parse_SimpleGet_TE_Chunked_NoFilter_ErrorLeadsToLowercaseChunksize) {
    const char *req = "GET /home HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1F\r\nAAAABBBBCCCCDDDDEEEEFFFFGGGGHH\r\n0\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_STREQ(hc.host_str->c_str(), " localhost");
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_STREQ(hc.te_str->c_str(), " chunked");
    //ASSERT_STREQ(hc.body_str->c_str(), "1f\r\nAAAABBBBCCCCDDDDEEEEFFFFGGGGHH\r\n0\r\n\r\n"); // F converted to lowercase
    ASSERT_STREQ(hc.body_str->c_str(), "AAAABBBBCCCCDDDDEEEEFFFFGGGGHH\r\n0\r\n\r\n"); // F converted to lowercase
}

TEST(HashComp, Parse_SimpleGet_ChunkBody_NoTE_NoFilter) {
    const char *req = "GET /home HTTP/1.1\r\n\r\n7\r\nABCDEFG\r\na\r\n0123456789\r\nB\r\nABCDEFGHIJK\r\n0\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_EQ(hc.host_str, nullptr);
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_EQ(hc.te_str, nullptr);
    ASSERT_STREQ(hc.body_str->c_str(), "7\r\nABCDEFG\r\na\r\n0123456789\r\nB\r\nABCDEFGHIJK\r\n0\r\n\r\n");
}

TEST(HashComp, Parse_SimpleGet_TE_Chunked_MultiChunk_NoFilter) {
    const char *req = "GET /home HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nABCDEFG\r\na\r\n0123456789\r\nB\r\nABCDEFGHIJK\r\n0\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_EQ(hc.host_str, nullptr);
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_STREQ(hc.te_str->c_str(), " chunked");
    ASSERT_STREQ(hc.body_str->c_str(), "ABCDEFG0123456789ABCDEFGHIJK");
}

TEST(HashComp, Parse_SimpleGet_TE_NoFilter) {
    const char *req = "GET /home HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nABCDEFG\r\n0\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_STREQ(hc.host_str->c_str(), " localhost");
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_STREQ(hc.te_str->c_str(), " chunked");
    ASSERT_STREQ(hc.body_str->c_str(), "ABCDEFG");
}

TEST(HashComp, Parse_SimpleGet_TE_ChunkExt_NoFilter) {
    const char *req = "GET /home HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n7;a=1;b=2\r\nABCDEFG\r\n0;c=3   3\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_STREQ(hc.host_str->c_str(), " localhost");
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_STREQ(hc.te_str->c_str(), " chunked");
    ASSERT_STREQ(hc.body_str->c_str(), "ABCDEFG");
}

TEST(HashComp, Parse_SimpleGet_CaseInsensitiveHdrs) {
    const char *req = "GET /home HTTP/1.1\r\nhOsT: localhost\r\nTransFer-encodiNg: chunked\r\ncontEnt-Length: 10\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_STREQ(hc.host_str->c_str(), " localhost");
    ASSERT_STREQ(hc.cl_str->c_str(), " 10");
    ASSERT_STREQ(hc.te_str->c_str(), " chunked");
    ASSERT_EQ(hc.body_str, nullptr);
}

TEST(HashComp, Parse_DuplicateKnownHdrs) {
    const char *req = "GET /home HTTP/1.1\r\n"
                      "hOsT: localhost\r\nTransFer-encodiNg: chunked\r\ncontEnt-Length: 10\r\n"
                      "HOST: value\r\ntransfer-encoding: asdfghjkl;\r\nContent-Length: 50\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_STREQ(hc.host_str->c_str(), " localhost");
    ASSERT_STREQ(hc.cl_str->c_str(), " 10");
    ASSERT_STREQ(hc.te_str->c_str(), " chunked");
    ASSERT_EQ(hc.rem_host_str.size(), 1);
    ASSERT_STREQ(hc.rem_host_str[0].c_str(), "host: value");
    ASSERT_EQ(hc.rem_cl_str.size(), 1);
    ASSERT_STREQ(hc.rem_cl_str[0].c_str(), "content-length: 50");
    ASSERT_EQ(hc.rem_te_str.size(), 1);
    ASSERT_STREQ(hc.rem_te_str[0].c_str(), "transfer-encoding: asdfghjkl;");
    ASSERT_EQ(hc.body_str, nullptr);
}

TEST(HashComp, Parse_DuplicateRemainHdrs_Filter) {
    const char *req = "GET /home HTTP/1.1\r\nhdr1: value\r\nHdR1: asdfghjkl;\r\n\r\n";
    ProxyConfig f;
    f.host = "localhost";
    f.headers.insert("hdr1");
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_EQ(hc.host_str, nullptr);
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_EQ(hc.te_str, nullptr);
    ASSERT_EQ(hc.body_str, nullptr);
}

TEST(HashComp, Multiple_CL_TE_And_Host_In_RemainHdrs) {
    const char *req = "GET /home HTTP/1.1\r\n"
                      "Host: localhost\r\nContent-Length: 10\r\nTransfer-Encoding: identity\r\n"
                      "Host: test.com\r\nContent-Length: 50\r\nTransfer-Encoding: chunked\r\n"
                      "\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_EQ(*hc.host_str, " localhost");
    ASSERT_EQ(*hc.cl_str, " 10");
    ASSERT_EQ(*hc.te_str, " identity");
    ASSERT_EQ(hc.rem_host_str.size(), 1);
    ASSERT_EQ(hc.rem_cl_str.size(), 1);
    ASSERT_EQ(hc.rem_te_str.size(), 1);
    ASSERT_EQ(hc.body_str, nullptr);
}

TEST(HashComp, Special_CL_TE_And_Host_In_RemainHdrs) {
    const char *req = "GET /home HTTP/1.1\r\n"
                      " Host: localhost\r\ncontent-length  : 10\r\n\tTransfer-encoding  : identity\r\n"
                      "\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_EQ(hc.host_str, nullptr);
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_EQ(hc.te_str, nullptr);
    ASSERT_EQ(hc.rem_host_str.size(), 1);
    ASSERT_EQ(hc.rem_cl_str.size(), 1);
    ASSERT_EQ(hc.rem_te_str.size(), 1);
    ASSERT_EQ(hc.body_str, nullptr);
}

TEST(HashComp, Expect_and_Connection_Headers) {
    const char *req = "GET /home HTTP/1.1\r\n"
                      "Expect: 100-continue\r\n"
                      "Connection: Close\r\n"
                      "\r\n";
    ProxyConfig f;
    f.host = "localhost";
    HashComp hc;
    hashcomp_common(req, &f, &hc);

    ASSERT_STREQ(hc.reqline_str->c_str(), "GET /home HTTP/1.1");
    ASSERT_EQ(hc.host_str, nullptr);
    ASSERT_EQ(hc.cl_str, nullptr);
    ASSERT_EQ(hc.te_str, nullptr);
    ASSERT_STREQ(hc.expect_str->c_str(), " 100-continue");
    ASSERT_STREQ(hc.conn_str->c_str(), " Close");
    ASSERT_EQ(hc.rem_host_str.size(), 0);
    ASSERT_EQ(hc.rem_cl_str.size(), 0);
    ASSERT_EQ(hc.rem_te_str.size(), 0);
    ASSERT_EQ(hc.body_str, nullptr);
}

TEST(HashComp, Whitespace_TE_Chunk_Values) {
    HashComp hc;
    EXPECT_TRUE(Util::special_match("chunked", "chunked"));

    // whitespace before/after
    EXPECT_TRUE(Util::special_match(" chunked", "chunked"));
    EXPECT_TRUE(Util::special_match("\tchunked", "chunked"));
    EXPECT_TRUE(Util::special_match("chunked ", "chunked"));
    EXPECT_TRUE(Util::special_match("chunked\t", "chunked"));
    EXPECT_TRUE(Util::special_match("  chunked\t\t", "chunked"));
    EXPECT_TRUE(Util::special_match(" \tchunked\t ", "chunked"));
}

/*
 * Disabled because we now only check for whitespace
 */
TEST(HashComp, DISABLED_Special_TE_Chunk_Values) {
    HashComp hc;

    // special characters before/after
    EXPECT_TRUE(Util::special_match("*chunked", "chunked"));
    EXPECT_TRUE(Util::special_match("chunked?", "chunked"));
    EXPECT_TRUE(Util::special_match("&\xe2""chunked!!", "chunked"));

    // combination special chars and whitespace
    EXPECT_TRUE(Util::special_match(" chunked!", "chunked"));
    EXPECT_TRUE(Util::special_match("&chunked ", "chunked"));
    EXPECT_TRUE(Util::special_match("  @chunked  *", "chunked"));

    EXPECT_FALSE(Util::special_match("", "chunked"));
    EXPECT_FALSE(Util::special_match("asdf", "chunked"));
    EXPECT_FALSE(Util::special_match("identity", "chunked"));
    EXPECT_FALSE(Util::special_match("chunkedf", "chunked"));
    EXPECT_FALSE(Util::special_match("fchunked", "chunked"));
    EXPECT_FALSE(Util::special_match(" chunkedd", "chunked"));
    EXPECT_FALSE(Util::special_match("  &&chunked  &a", "chunked"));
    EXPECT_FALSE(Util::special_match("5chunked ", "chunked"));
    EXPECT_FALSE(Util::special_match(" chunked7", "chunked"));
}

TEST(HashComp, chunkedf_Is_Not_Chunked) {
    const char* req = "POST /reqid=_REQID_ HTTP/1.1\r\n"
                      "host: localhost\r\n"
                      "xxxxxxxxxxxxxxxxx: identity\r\n"
                      "transfer-encoding: chunkedf\xe2\r\n"
                      "transfer-encoding: chunkedf\r\n"
                      "cont!ent-length: 10\r\n"
                      "!content-length: 10\r\n"
                      "X-Forwarded-Host: localhost\r\n"
                      "X-Forwarded-Proto: https\r\n"
                      "Accept-Encoding: gzip\r\n"
                      "X-Forwarded-For: 127.0.0.1\r\n"
                      "\r\n"
                      "BBBBBBBBBB";
    ProxyConfig f;
    f.host = "localhost";

    HashComp hc;
    hashcomp_common(req, &f, &hc);

    EXPECT_EQ(hc.cl_str, nullptr);
    EXPECT_EQ(hc.chnk_err, 0);
}

TEST(HashComp, EveryValIsNonZero) {
    /**
     * This test case has a sibling in Normalize_Fixture.AllFieldsNormalizedToZero.
     * It uses the same req and ensures that specific fields are normalized to zero.
     */

    const char* req = "POST /home HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      " Host: test.com\r\n"
                      "Content-Length: 10\r\n"
                      "Transfer-Encoding: chunked\r\n"
                      "content-length : 15\r\n"
                      "transfer-encoding: identity\r\n"
                      "connection: close\r\n"
                      "Expect: 100-continue\r\n"
                      "Connection: Cookie\r\n"
                      "expect: nothing\r\n"
                      "\r\n"
                      "A\r\n"
                      "0123456789\r\n"
                      "0!\r\n"
                      "\r\n";

    ProxyConfig f;
    f.host = "localhost";

    HashComp hc;
    hashcomp_common(req, &f, &hc);
    hc.hash_indiv();

    EXPECT_TRUE(hc.reqline_str != nullptr);
    EXPECT_NE(hc.method_hash, 0);
    EXPECT_NE(hc.version_hash, 0);
    EXPECT_NE(hc.host_hash, 0);
    EXPECT_TRUE(!hc.rem_host_str.empty());
    EXPECT_NE(hc.rem_host_hash, 0);
    EXPECT_TRUE(hc.cl_str != nullptr);
    EXPECT_NE(hc.cl_hash, 0);
    EXPECT_TRUE(!hc.rem_cl_str.empty());
    EXPECT_NE(hc.rem_cl_hash, 0);
    EXPECT_NE(hc.te_hash, 0);
    EXPECT_TRUE(!hc.rem_te_str.empty());
    EXPECT_NE(hc.rem_te_hash, 0);
    EXPECT_NE(hc.conn_hash, 0);
    EXPECT_TRUE(!hc.rem_conn_str.empty());
    EXPECT_NE(hc.rem_conn_hash, 0);
    EXPECT_NE(hc.expect_hash, 0);
    EXPECT_TRUE(!hc.rem_expect_str.empty());
    EXPECT_NE(hc.rem_expect_hash, 0);
    EXPECT_TRUE(hc.body_str != nullptr);
    EXPECT_NE(hc.body_hash, 0);
    EXPECT_NE(hc.chnk_err, 0);
}


TEST(HashComp, StrCmpHelper) {
    std::string s1 = "asdf";
    std::string s2 = "jkl;";
    std::string s3 = "asdf";

    ASSERT_TRUE(Util::str_ptr_equals(nullptr, nullptr));
    ASSERT_FALSE(Util::str_ptr_equals(&s1, nullptr));
    ASSERT_FALSE(Util::str_ptr_equals(nullptr, &s1));
    ASSERT_TRUE(Util::str_ptr_equals(&s1, &s1));
    ASSERT_FALSE(Util::str_ptr_equals(&s1, &s2));
    ASSERT_TRUE(Util::str_ptr_equals(&s1, &s3));
}