#include <gtest/gtest.h>
#include <cstring>
#include "../h1_parser.h"

TEST(H1Parser, SimpleGET) {
    const char *req = "GET /home HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\n\r\nABCDEFG";
    size_t sz = strlen(req);

    H1Parser h;
    h.parse(req, sz);
    ASSERT_NE(h.reqline, nullptr);
    ASSERT_STREQ(h.reqline->c_str(), "GET /home HTTP/1.1");

    ASSERT_EQ(h.headers.size(), 2);
    ASSERT_STREQ(h.headers[0]->c_str(), "Host: localhost");
    ASSERT_STREQ(h.headers[1]->c_str(), "Content-Length: 7");

    ASSERT_NE(h.body, nullptr);
    ASSERT_STREQ(h.body->c_str(), "ABCDEFG");
}

TEST(H1Parser, DupHeaders) {
    const char *req = "GET /home HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\nContent-Length: 7\r\n\r\nABCDEFG";
    size_t sz = strlen(req);

    H1Parser h;
    h.parse(req, sz);
    ASSERT_NE(h.reqline, nullptr);
    ASSERT_STREQ(h.reqline->c_str(), "GET /home HTTP/1.1");

    ASSERT_EQ(h.headers.size(), 3);
    ASSERT_STREQ(h.headers[0]->c_str(), "Host: localhost");
    ASSERT_STREQ(h.headers[1]->c_str(), "Content-Length: 7");
    ASSERT_STREQ(h.headers[2]->c_str(), "Content-Length: 7");

    ASSERT_NE(h.body, nullptr);
    ASSERT_STREQ(h.body->c_str(), "ABCDEFG");
}

TEST(H1Parser, NoBody) {
    const char *req = "GET /home HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\n\r\n";
    size_t sz = strlen(req);

    H1Parser h;
    h.parse(req, sz);
    ASSERT_NE(h.reqline, nullptr);
    ASSERT_STREQ(h.reqline->c_str(), "GET /home HTTP/1.1");

    ASSERT_EQ(h.headers.size(), 2);
    ASSERT_STREQ(h.headers[0]->c_str(), "Host: localhost");
    ASSERT_STREQ(h.headers[1]->c_str(), "Content-Length: 7");

    ASSERT_NE(h.body, nullptr);
    ASSERT_STREQ(h.body->c_str(), "");
}

TEST(H1Parser, Base) {
    H1Parser h;
    ASSERT_EQ(h.reqline, nullptr);
    ASSERT_EQ(h.headers.size(), 0);
    ASSERT_EQ(h.body, nullptr);
}

TEST(H1Parser, Empty) {
    H1Parser h;
    h.parse("", 0);
    ASSERT_EQ(h.reqline, nullptr);
    ASSERT_EQ(h.headers.size(), 0);
    ASSERT_EQ(h.body, nullptr);
}

TEST(H1Parser, NoDoubleCRLF) {
    const char *req = "GET /home HTTP/1.1\r\n";
    size_t sz = strlen(req);
    H1Parser h;
    h.parse(req, sz);
    ASSERT_EQ(h.body, nullptr);
}