
#include <gtest/gtest.h>
#include "../callbacks.h"
#include "../../h2_serializer/src/frames/frames.h"
#include "../../h2_serializer/src/deserializer.h"

typedef hpack::HPacker::PrefixType PrefType;
typedef hpack::HPacker::IndexingType IdxType;

void overwrite_authority_path_test(const std::string &hdr_name, const std::string &orig_val, const std::string &filt_val, const std::string &new_val) {
    ProxyConfig filt;
    filt.authority = filt_val;

    HeadersFrame hf;
    hf.len = 30;
    hf.flags = FLAG_END_HEADERS;
    hf.stream_id = 0x00000001;
    hf.add_header(":method", "POST", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    hf.add_header(":scheme", "http", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    hf.add_header(":path", "http://" GRAMMAR_AUTH "/reqid=4", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    hf.add_header(":authority", orig_val, PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    hf.add_header("host", orig_val, PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    hf.add_header(" host\t", orig_val, PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);

    char buf[256];
    hpack::HPacker hpe;
    size_t sz = hf.serialize(buf, 256, &hpe, false);

    char *new_data;
    size_t newsz = preprocess_req(filt, (uint8_t*) buf, sz, &new_data);
    H2Stream* h2strm = Deserializer::deserialize_stream(new_data, newsz);

    ASSERT_EQ(h2strm->size(), 1);
    auto *hf_mod = dynamic_cast<HeadersFrame*>(h2strm->at(0));
    ASSERT_NE(hf_mod, nullptr);
    bool pass = false;
    for (auto& hp : hf_mod->hdr_pairs) {
        if (hp.first == hdr_name) {
            ASSERT_EQ(hp.second, new_val);
            pass = true;
        }
    }

    ASSERT_TRUE(pass);

    delete[] new_data;
    delete h2strm->at(0);
    delete h2strm;
}

TEST(TestCallbacks, OverwriteAuthority) {
    overwrite_authority_path_test(":authority", GRAMMAR_AUTH, "NEWVAL", "NEWVAL");
}

TEST(TestCallbacks, OverwriteAuthority_As_SubString) {
    overwrite_authority_path_test(":authority", "&" GRAMMAR_AUTH " ", "NEWVAL", "&NEWVAL ");
}

TEST(TestCallbacks, OverwriteAuthority_Broken_Stays_Broken) {
    overwrite_authority_path_test(":authority", "DEADBEEF", "NEWVAL", "DEADBEEF");
}

TEST(TestCallbacks, OverwritePath) {
    overwrite_authority_path_test(":path", "", "NEWVAL", "http://NEWVAL/reqid=4");
}

TEST(TestCallbacks, OverwriteHost) {
    overwrite_authority_path_test("host", GRAMMAR_AUTH, "NEWVAL", "NEWVAL");
}

TEST(TestCallbacks, OverwriteHost_As_SubString) {
    overwrite_authority_path_test("host", "&" GRAMMAR_AUTH " ", "NEWVAL", "&NEWVAL ");
}

TEST(TestCallbacks, OverwriteSpecialHost) {
    overwrite_authority_path_test(" host\t", GRAMMAR_AUTH, "NEWVAL", "NEWVAL");
}

TEST(TestCallbacks, OverwriteSpecialHost_As_SubString) {
    overwrite_authority_path_test(" host\t", "&" GRAMMAR_AUTH " ", "NEWVAL", "&NEWVAL ");
}

TEST(TestCallbacks, OverwriteAuthority_AllowedWhenBeyondMaxSize) {
    /*
     * akamai.h2fuzz.website
     * cloudflare.h2fuzz.website
     * d2plqgx06492db.cloudfront.net
     * h2fuzz.azureedge.net
     * h2fuzz.freetls.fastly.net
     */
    ProxyConfig filt;
    filt.authority = "d2plqgx06492db.cloudfront.net";  // longest one in our actual dataset

    HeadersFrame hf;
    hf.flags = FLAG_END_HEADERS | FLAG_PADDED;
    hf.stream_id = 0x00000001;
    hf.add_header(":authority", GRAMMAR_AUTH, PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    hf.padlen = 255;
    hf.padding.insert(hf.padding.begin(), hf.padlen, 0);

    char buf[512];
    hpack::HPacker hpe;
    size_t sz = hf.serialize(buf, 512, &hpe, false);

    char *new_data;
    size_t newsz = preprocess_req(filt, (uint8_t*) buf, sz, &new_data);
}

TEST(TestCallbacks, DISABLED_OverflowIssues) {
    ProxyConfig filt;
    filt.authority = "Tomorrow, and tomorrow, and tomorrow,"
                     "Creeps in this petty pace from day to day,"
                     "To the last syllable of recorded time;"
                     "And all our yesterdays have lighted fools"
                     "The way to dusty death. Out, out, brief candle!"
                     "Life's but a walking shadow, a poor player,"
                     "That struts and frets his hour upon the stage,"
                     "And then is heard no more. It is a tale"
                     "Told by an idiot, full of sound and fury,"
                     "Signifying nothing.";

    HeadersFrame hf;
    hf.flags = FLAG_END_HEADERS;
    hf.stream_id = 0x00000001;
    for (int i = 0; i < 2; ++i) {
        hf.add_header(":path", "http://" GRAMMAR_AUTH "/reqid=4", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
        hf.add_header(":authority", GRAMMAR_AUTH, PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
        hf.add_header("host", GRAMMAR_AUTH, PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
        hf.add_header(" host&", GRAMMAR_AUTH, PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
    }

    char buf[2048];
    hpack::HPacker hpe;
    size_t sz = hf.serialize(buf, 2048, &hpe, false);

    char *new_data;
    size_t newsz = preprocess_req(filt, (uint8_t*) buf, sz, &new_data);
}