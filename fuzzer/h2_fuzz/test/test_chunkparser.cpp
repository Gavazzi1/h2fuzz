#include <gtest/gtest.h>
#include "../chunkparser.h"

TEST(ChunkParse, Empty) {
    ChunkParser pars;
    std::string body = "0\r\n\r\n";

    int n_read = pars.parse_chunked(body.c_str(), body.length());
    ASSERT_EQ(n_read, body.length());
    ASSERT_EQ(pars.err, 0);
    ASSERT_EQ(pars.body, "");
}

TEST(ChunkParse, OneChunk) {
    ChunkParser pars;
    std::string body = "5\r\nAAAAA\r\n0\r\n\r\n";

    int n_read = pars.parse_chunked(body.c_str(), body.length());
    ASSERT_EQ(n_read, body.length());
    ASSERT_EQ(pars.err, 0);
    ASSERT_EQ(pars.body, "AAAAA");
}

TEST(ChunkParse, TwoChunks) {
    ChunkParser pars;
    std::string body = "5\r\nAAAAA\r\n5\r\nBBBBB\r\n0\r\n\r\n";

    int n_read = pars.parse_chunked(body.c_str(), body.length());
    ASSERT_EQ(n_read, body.length());
    ASSERT_EQ(pars.err, 0);
    ASSERT_EQ(pars.body, "AAAAABBBBB");
}

TEST(ChunkParse, CaseInsensitiveHex) {
    ChunkParser pars;
    std::string body = "A\r\n0123456789\r\nb\r\n01234567890\r\n0\r\n\r\n";

    int n_read = pars.parse_chunked(body.c_str(), body.length());
    ASSERT_EQ(n_read, body.length());
    ASSERT_EQ(pars.err, 0);
    ASSERT_EQ(pars.body, "012345678901234567890");
}

TEST(ChunkParse, MultiCharHex) {
    ChunkParser pars;
    std::string chunk(266, '.');
    std::string body = "10a\r\n" + chunk + "\r\n0\r\n\r\n";

    int n_read = pars.parse_chunked(body.c_str(), body.length());
    ASSERT_EQ(n_read, body.length());
    ASSERT_EQ(pars.err, 0);
    ASSERT_EQ(pars.body, chunk);
}

TEST(ChunkParse, BadChunk) {
    ChunkParser pars;
    std::string body = "5&\r\nAAAAA\r\n0\r\n\r\n";

    pars.parse_chunked(body.c_str(), body.length());
    ASSERT_EQ(pars.err, BADHEX);
    ASSERT_EQ(pars.body, "");  // body is whatever was parsed so far at point of error

    ChunkParser pars2;
    std::string body2 = "5\r\nAAAAA\r\n%5\r\nBBBBB\r\n0\r\n\r\n";

    pars2.parse_chunked(body2.c_str(), body2.length());
    ASSERT_EQ(pars2.err, BADHEX);
    ASSERT_EQ(pars2.body, "AAAAA");  // body is whatever was parsed so far at point of error
}

TEST(ChunkParse, MissingLastChunk) {
    ChunkParser pars;
    std::string body = "5\r\nAAAAA\r\n";

    int n_read = pars.parse_chunked(body.c_str(), body.length());
    ASSERT_EQ(n_read, body.length());
    ASSERT_EQ(pars.err, NO_LAST_CHUNK);
    ASSERT_EQ(pars.body, "AAAAA");
}

TEST(ChunkParse, MissingChunkData) {
    ChunkParser pars;
    std::string body = "5\r\n";

    int n_read = pars.parse_chunked(body.c_str(), body.length());
    ASSERT_EQ(n_read, body.length());
    ASSERT_EQ(pars.err, NODATA);
    ASSERT_EQ(pars.body, "");
}

TEST(ChunkParse, MissingSizeCRLF) {
    std::vector<std::string> bodies {
        "5",
        "5\r\nAAAAA\r\n0",
    };

    for (const auto& body : bodies) {
        ChunkParser pars;
        pars.parse_chunked(body.c_str(), body.length());
        ASSERT_EQ(pars.err, NOSIZECRLF);
    }
}

TEST(ChunkParse, MissingChunkCRLF) {
    std::vector<std::string> bodies {
            "5\r\nAAAAA",
            "5\r\nAAAAA\r\n0\r\n",
            "5\r\nAAAAABB"
    };

    for (const auto& body : bodies) {
        ChunkParser pars;
        pars.parse_chunked(body.c_str(), body.length());
        ASSERT_EQ(pars.err, NOCHUNKCRLF);
    }
}

TEST(ChunkParse, MissingSizeLF) {
    std::vector<std::string> bodies {
            "5\rAAAAA\r\n0\r\n\r\n",
            "5\r\nAAAAA\r\n0\r\r\n"
    };

    for (const auto& body : bodies) {
        ChunkParser pars;
        pars.parse_chunked(body.c_str(), body.length());
        ASSERT_EQ(pars.err, NOSIZELF);
    }
}

TEST(ChunkParse, MissingChunkLF) {
    std::vector<std::string> bodies {
            "5\r\nAAAAA\r0\r\n\r\n",
            "5\r\nAAAAA\r\n0\r\n\r"
    };

    for (const auto& body : bodies) {
        ChunkParser pars;
        pars.parse_chunked(body.c_str(), body.length());
        ASSERT_EQ(pars.err, NOCHUNKLF);
    }
}