#include <gtest/gtest.h>
#include "../proxy_config.h"

TEST(Test_Filter_Parse, Test_1) {
    ProxyConfig *f = ProxyConfig::get_proxy_config("test_1");
    ASSERT_EQ(f->host, "HOST_VAL");
    ASSERT_EQ(f->authority, "AUTHORITY_VAL");
    ASSERT_EQ(f->headers.size(), 0);
    delete f;
}

TEST(Test_Filter_Parse, Test_2) {
    ProxyConfig *f = ProxyConfig::get_proxy_config("test_2");
    ASSERT_EQ(f->host, "INCOMING_HOST");
    ASSERT_EQ(f->authority, "OUTGOING_AUTH");
    ASSERT_EQ(f->headers.size(), 3);
    ASSERT_NE(f->headers.find("hdr_name_1"), f->headers.end());
    ASSERT_NE(f->headers.find("Hdr_Name_2"), f->headers.end());
    ASSERT_NE(f->headers.find("HDR_NAME_3"), f->headers.end());
    delete f;
}

TEST(Test_Filter_Parse, DISABLED_Nginx) {
    ProxyConfig *f = ProxyConfig::get_proxy_config("nginx");
    ASSERT_EQ(f->host, "127.0.0.1:8080");
    ASSERT_EQ(f->authority, "localhost:443");
    ASSERT_EQ(f->headers.size(), 1);
    ASSERT_NE(f->headers.find("connection"), f->headers.end());
    delete f;
}

TEST(Test_Filter_Parse, DISABLED_Caddy) {
    ProxyConfig *f = ProxyConfig::get_proxy_config("caddy");
    ASSERT_EQ(f->host, "localhost:443");
    ASSERT_EQ(f->authority, "localhost:443");
    ASSERT_EQ(f->headers.size(), 3);
    ASSERT_NE(f->headers.find("accept-encoding"), f->headers.end());
    ASSERT_NE(f->headers.find("x-forwarded-for"), f->headers.end());
    ASSERT_NE(f->headers.find("x-forwarded-proto"), f->headers.end());
    delete f;
}

TEST(Test_Filter_Parse, Varnish) {
    ProxyConfig *f = ProxyConfig::get_proxy_config("varnish");
    ASSERT_EQ(f->host, "localhost");
    ASSERT_EQ(f->authority, "localhost");
    ASSERT_EQ(f->headers.size(), 8);
    //ASSERT_NE(f.headers.find("accept-encoding"), f.headers.end());
    //ASSERT_NE(f.headers.find("x-forwarded-for"), f.headers.end());
    //ASSERT_NE(f.headers.find("x-forwarded-proto"), f.headers.end());
    delete f;
}