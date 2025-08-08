
#include <gtest/gtest.h>
#include "../normalizer.h"

/** Test fixture to abstract away headers setup */
class Normalize_Fixture : public ::testing::Test {
protected:

    static std::vector<HashComp*> parse_hash_normalize(const char **reqs, int n) {
        ProxyConfig f;
        f.host = "localhost";
        std::vector<HashComp*> out;
        for (int i = 0; i < n; ++i) {
            H1Parser hp;
            auto *hc = new HashComp();
            hp.parse(reqs[i], strlen(reqs[i]));
            hc->parse(hp, f);
            hc->hash_indiv();
            out.emplace_back(hc);
        }

        Normalizer::normalize(out.data(), n);
        return out;
    }

    static std::vector<HashComp*> parse_hash_normalize_two(const char *req1, const char *req2) {
        const char *reqs[2];
        reqs[0] = req1;
        reqs[1] = req2;
        return parse_hash_normalize(reqs, 2);
    }

    static void del_hc(const std::vector<HashComp*>& v) {
        for (auto hc : v) {
            delete hc;
        }
    }
};


TEST_F(Normalize_Fixture, OneEmpty) {
    const char *req1 = "";  // main won't pass empty string to H1Parser, but this assumes we do at some point
    const char *req2 = "GET /a HTTP/1.1\r\nhost: localhost\r\nhdr: val\r\ncontent-length: 5\r\n\r\nabcde";
    auto v = parse_hash_normalize_two(req1, req2);
    ASSERT_NE(v[0]->hash_full(), v[1]->hash_full());
    del_hc(v);
}

TEST_F(Normalize_Fixture, ExampleFromFuzzer) {
    const char *req1 =
            "POST /reqid=6205 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "19\r\n"
            "5\r\nBBBBB\r\n0\r\n\r\n5\r\nBBBBB\r\n\r\n"
            "0\r\n\r\n";

    const char *req2 =
            "POST /reqid=6205 HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "Content-Length: 25\r\n"
            "Connection: close\r\n\r\n"
            "5\r\nBBBBB\r\n0\r\n\r\n5\r\nBBBBB\r\n";

    auto v = parse_hash_normalize_two(req1, req2);

    ASSERT_EQ(v[0]->host_hash, v[1]->host_hash);
    ASSERT_EQ(v[0]->method_hash, v[1]->method_hash);
    ASSERT_EQ(v[0]->method_hash, 0);
    ASSERT_EQ(v[0]->body_hash, 0);
    ASSERT_EQ(v[0]->body_hash, v[1]->body_hash);

    del_hc(v);
}

TEST_F(Normalize_Fixture, NormPathSameDiff) {
    const char *req1 = "POST /a HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const char *req2 = "POST /a HTTP/1.1\r\n\r\n";
    auto v1 = parse_hash_normalize_two(req1, req2);
    ASSERT_EQ(v1[0]->method_hash, 0);
    ASSERT_EQ(v1[0]->method_hash, v1[1]->method_hash);

    const char *req3 = "POST /b HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const char *req4 = "POST /b HTTP/1.1\r\n\r\n";
    auto v2 = parse_hash_normalize_two(req3, req4);
    ASSERT_EQ(v2[0]->method_hash, 0);
    ASSERT_EQ(v2[0]->method_hash, v2[1]->method_hash);

    // we should see the same hashes across these requests because we normalize by path
    ASSERT_EQ(v1[0]->hash_full(), v2[0]->hash_full());
    ASSERT_EQ(v1[1]->hash_full(), v2[1]->hash_full());
    ASSERT_NE(v1[0]->hash_full(), v1[1]->hash_full());  // check that we still see a difference

    del_hc(v1);
    del_hc(v2);
}

// disabled because we no longer add non-special headers to remaining-headers
TEST_F(Normalize_Fixture, DISABLED_NormCLBodySameDiff) {
    const char *req1 = "POST /a HTTP/1.1\r\nContent-Length: 5\r\nHdr: Val\r\n\r\nABCDE";
    const char *req2 = "POST /a HTTP/1.1\r\ncontent-length: 5\r\n\r\nABCDE";
    auto v1 = parse_hash_normalize_two(req1, req2);
    ASSERT_EQ(v1[0]->cl_hash, 0);
    ASSERT_EQ(v1[0]->cl_hash, v1[1]->cl_hash);

    const char *req3 = "POST /a HTTP/1.1\r\nContent-Length: 7\r\nHdr: Val\r\n\r\nABCDEFG";
    const char *req4 = "POST /a HTTP/1.1\r\nconTent-lEngth: 7\r\n\r\nABCDEFG";
    auto v2 = parse_hash_normalize_two(req3, req4);
    ASSERT_EQ(v2[0]->cl_hash, 0);
    ASSERT_EQ(v2[0]->cl_hash, v2[1]->cl_hash);

    // we should see the same hashes across these requests because we normalize the CL value and body
    ASSERT_EQ(v1[0]->hash_full(), v2[0]->hash_full());
    ASSERT_EQ(v1[1]->hash_full(), v2[1]->hash_full());
    ASSERT_NE(v1[0]->hash_full(), v1[1]->hash_full());  // check that we still see a difference

    del_hc(v1);
    del_hc(v2);
}

TEST_F(Normalize_Fixture, NormBodySameDiff) {
    const char *req1 = "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nABCDE";
    const char *req2 = "POST& /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nABCDE";
    auto v1 = parse_hash_normalize_two(req1, req2);
    ASSERT_EQ(v1[0]->body_hash, 0);
    ASSERT_EQ(v1[0]->body_hash, v1[1]->body_hash);

    const char *req3 = "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nFGHIJ";
    const char *req4 = "POST& /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nFGHIJ";
    auto v2 = parse_hash_normalize_two(req3, req4);
    ASSERT_EQ(v2[0]->body_hash, 0);
    ASSERT_EQ(v2[0]->body_hash, v2[1]->body_hash);

    // we should see the same hashes across these requests because we normalize the CL value and body
    ASSERT_EQ(v1[0]->hash_full(), v2[0]->hash_full());
    ASSERT_EQ(v1[1]->hash_full(), v2[1]->hash_full());
    ASSERT_NE(v1[0]->hash_full(), v1[1]->hash_full());  // check that we still see a difference

    del_hc(v1);
    del_hc(v2);
}

TEST_F(Normalize_Fixture, NormBody_NoNewDiffWhenOnlyOneBody) {
    const char *req1 = "POST /a HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const char *req2 = "POST& /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nABCDE";
    auto v1 = parse_hash_normalize_two(req1, req2);
    ASSERT_NE(v1[0]->hash_full(), v1[1]->hash_full());

    const char *req3 = "POST /a HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const char *req4 = "POST& /a HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc123u&me";
    auto v2 = parse_hash_normalize_two(req3, req4);

    // we should see the same hashes across these requests because we normalize the CL value and body
    ASSERT_EQ(v1[0]->hash_full(), v2[0]->hash_full());
    ASSERT_EQ(v1[1]->hash_full(), v2[1]->hash_full());

    del_hc(v1);
    del_hc(v2);
}

TEST_F(Normalize_Fixture, NormAll_NormToZeroNotSameAsNotExisting) {
    const char *req1 = "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";  // not sure how to simulate no path
    const char *req2 = "POST /a HTTP/1.1\r\nContent-Length: 5\r\nHdr: Val\r\n\r\nABCDE";
    const char *req3 = "POST /a HTTP/1.1\r\nContent-Length: 5\r\nHdr: Val\r\n\r\nABCDE";

    const char *reqs[3];
    reqs[0] = req1;
    reqs[1] = req2;
    reqs[2] = req3;
    auto v = parse_hash_normalize(reqs, 3);
    ASSERT_NE(v[0]->hash_full(), v[1]->hash_full());
    ASSERT_EQ(v[1]->hash_full(), v[2]->hash_full());

    // Same type of difference. Final hashes should be identical because no new behavior is observed
    const char *req4 = "POST /b HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";  // not sure how to simulate no path
    const char *req5 = "POST /b HTTP/1.1\r\nContent-Length: 10\r\nHdr2: Val2\r\n\r\nABCDEFGHIJ";
    const char *req6 = "POST /b HTTP/1.1\r\nContent-Length: 10\r\nHdr2: Val2\r\n\r\nABCDEFGHIJ";

    const char *reqs2[3];
    reqs2[0] = req4;
    reqs2[1] = req5;
    reqs2[2] = req6;
    auto v2 = parse_hash_normalize(reqs2, 3);
    ASSERT_NE(v2[0]->hash_full(), v2[1]->hash_full());
    ASSERT_EQ(v2[1]->hash_full(), v2[2]->hash_full());

    ASSERT_EQ(v[0]->hash_full(), v2[0]->hash_full());
    ASSERT_EQ(v[1]->hash_full(), v2[1]->hash_full());
    ASSERT_EQ(v[2]->hash_full(), v2[2]->hash_full());

    del_hc(v);
    del_hc(v2);
}

TEST_F(Normalize_Fixture, NormAll_DivergentBehaviorButSamePairs) {
    // req1 has mutation in path, lost a chunk somewhere, and doesn't forward custom headers
    const char *req1 = "POST& /a HTTP/1.0\r\nContent-Length: 3\r\n\r\nABC";
    const char *req2 = "POST /a HTTP/1.1\r\nContent-Length: 6\r\nHdr: Val\r\n\r\nABCDEF";
    const char *req3 = "POST /a HTTP/1.1\r\nContent-Length: 6\r\nHdr: Val\r\n\r\nABCDEF";

    const char *reqs[3];
    reqs[0] = req1;
    reqs[1] = req2;
    reqs[2] = req3;
    auto v = parse_hash_normalize(reqs, 3);

    // Same differences, but new path, method, and data sizes
    const char *req4 = "POST& /b HTTP/1.0\r\nContent-Length: 6\r\n\r\nABCDEF";
    const char *req5 = "POST /b HTTP/1.1\r\nContent-Length: 10\r\nHdr2: Val2\r\n\r\nABCDEFGHIJ";
    const char *req6 = "POST /b HTTP/1.1\r\nContent-Length: 10\r\nHdr2: Val2\r\n\r\nABCDEFGHIJ";

    const char *reqs2[3];
    reqs2[0] = req4;
    reqs2[1] = req5;
    reqs2[2] = req6;
    auto v2 = parse_hash_normalize(reqs2, 3);

    // TODO what is expected behavior? Right now, 2nd is considered a new difference

    del_hc(v);
    del_hc(v2);
}

TEST_F(Normalize_Fixture, NormAll_SameChunkedErrorGivesSameDifference) {
    const char *req1 = "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nABCDE";
    const char *req2 = "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nABCDE";
    auto v1 = parse_hash_normalize_two(req1, req2);
    ASSERT_NE(v1[0]->hash_full(), v1[1]->hash_full());

    const char *req3 = "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nABCDEF";
    const char *req4 = "POST /a HTTP/1.1\r\nContent-Length: 6\r\n\r\nABCDEF";
    auto v2 = parse_hash_normalize_two(req3, req4);

    // Requests have the same difference, so we should consider them the same difference
    ASSERT_EQ(v1[0]->hash_full(), v2[0]->hash_full());
    ASSERT_EQ(v1[1]->hash_full(), v2[1]->hash_full());

    del_hc(v1);
    del_hc(v2);
}

TEST_F(Normalize_Fixture, QuickFix_MethodIsPath_VersionIsMethod) {
    const char *req1 = "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nABCDE";
    const char *req2 = "POST /d HTTP/1.1\r\nContent-Length: 5\r\n\r\nABCDE";
    auto v1 = parse_hash_normalize_two(req1, req2);
    ASSERT_NE(v1[0]->hash_full(), v1[1]->hash_full());

    const char *req3 = "GET /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nABCDE";
    const char *req4 = "GET /b HTTP/1.1\r\nContent-Length: 5\r\n\r\nABCDE";
    auto v2 = parse_hash_normalize_two(req3, req4);

    // Requests have the same difference, so we should consider them the same difference
    ASSERT_EQ(v1[0]->hash_full(), v2[0]->hash_full());
    ASSERT_EQ(v1[1]->hash_full(), v2[1]->hash_full());

    del_hc(v1);
    del_hc(v2);
}

TEST_F(Normalize_Fixture, WeirdHost) {
    const char *req1 = "POST /a HTTP/1.1\r\nHost: PoKeMoN\r\n\r\n";
    const char *req2 = "POST /a HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto v1 = parse_hash_normalize_two(req1, req2);
    ASSERT_NE(v1[0]->hash_full(), v1[1]->hash_full());

    const char *req3 = "POST /a HTTP/1.1\r\nHost: LoLcAtS\r\n\r\n";
    const char *req4 = "POST /a HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto v2 = parse_hash_normalize_two(req3, req4);

    // Requests have the same difference, so we should consider them the same difference
    ASSERT_EQ(v1[0]->hash_full(), v2[0]->hash_full());
    ASSERT_EQ(v1[1]->hash_full(), v2[1]->hash_full());

    del_hc(v1);
    del_hc(v2);
}

TEST_F(Normalize_Fixture, ExtraHosts) {
    const char *req1 = "POST /a HTTP/1.1\r\nHost: localhost,asdf\r\n\r\n";
    const char *req2 = "POST /a HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto v1 = parse_hash_normalize_two(req1, req2);
    ASSERT_NE(v1[0]->hash_full(), v1[1]->hash_full());

    const char *req3 = "POST /a HTTP/1.1\r\nHost: localhost,deadbeef\r\n\r\n";
    const char *req4 = "POST /a HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto v2 = parse_hash_normalize_two(req3, req4);

    // Requests have the same difference, so we should consider them the same difference
    ASSERT_EQ(v1[0]->hash_full(), v2[0]->hash_full());
    ASSERT_EQ(v1[1]->hash_full(), v2[1]->hash_full());

    del_hc(v1);
    del_hc(v2);
}

TEST_F(Normalize_Fixture, AllFieldsNormalizedToZero) {
    /**
     * This test case has a sibling in HashComp.EveryValIsNonZero.
     * It uses the same req1 and ensures that before normalization, every hash value is nonzero.
     * Thus, this test ensures that specific fields are normalized to zero.
     */

    const char* req1 = "POST /home HTTP/1.1\r\n"
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
                      "0\r\n"
                      "\r\n";

    const char* req2 = "POST /home HTTP/1.1\r\n"
                       " Host: test.com\r\n"
                       "Host: localhost\r\n"
                       "content-length : 15\r\n"
                       "Content-Length: 10\r\n"
                       "Transfer-Encoding: chunked\r\n"
                       "transfer-encoding: identity\r\n"
                       "connection: close\r\n"
                       "Expect: 100-continue\r\n"
                       "Connection: Cookie\r\n"
                       "expect: nothing\r\n"
                       "\r\n"
                       "0123456789";

    auto v = parse_hash_normalize_two(req1, req2);
    EXPECT_NE(v[0]->hash_full(), v[1]->hash_full());
    EXPECT_EQ(v[0]->method_hash, 0);
    EXPECT_EQ(v[1]->method_hash, 0);
    EXPECT_EQ(v[0]->rem_host_hash, 0);
    EXPECT_EQ(v[1]->rem_host_hash, 0);
    EXPECT_EQ(v[0]->cl_hash, 0);
    EXPECT_EQ(v[1]->cl_hash, 0);
    EXPECT_EQ(v[0]->rem_cl_hash, 0);
    EXPECT_EQ(v[1]->rem_cl_hash, 0);
    EXPECT_EQ(v[0]->rem_te_hash, 0);
    EXPECT_EQ(v[1]->rem_te_hash, 0);
    EXPECT_EQ(v[0]->rem_conn_hash, 0);
    EXPECT_EQ(v[1]->rem_conn_hash, 0);
    EXPECT_EQ(v[0]->rem_expect_hash, 0);
    EXPECT_EQ(v[1]->rem_expect_hash, 0);
    EXPECT_EQ(v[0]->body_hash, 0);
    EXPECT_EQ(v[1]->body_hash, 0);

    del_hc(v);
}