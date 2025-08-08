#ifndef NEZHA_TEST_MUTATOR_COMMON_H
#define NEZHA_TEST_MUTATOR_COMMON_H

#include "../h2mutator.h"

typedef hpack::HPacker::PrefixType PrefType;
typedef hpack::HPacker::IndexingType IdxType;

/** Test mutator where return values from my_rand() are pulled from a list */
class TestMutator : public H2Mutator {
public:
    TestMutator(std::istream &in, const std::vector<unsigned int> &rands) : H2Mutator(in) {
        rands_ = rands;
        idx_ = 0;
    }

    TestMutator(char *buf, size_t sz, const std::vector<unsigned int> &rands) : H2Mutator(buf, sz) {
        rands_ = rands;
        idx_ = 0;
    }

    size_t size() {
        return this->strm_sz_;
    }

    unsigned int my_rand(unsigned int mod) override {
        assert(idx_ < rands_.size());
        return rands_[idx_++];
    }

    unsigned int get_mut_op() override {
        return my_rand(0);
    }

    unsigned int get_cross_op() override {
        return my_rand(0);
    }

    bool header_mut_rand() override {
        return my_rand(2);
    }

    size_t field_mut(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        return do_field_mutation(fr, f, m, MaxSize);
    }

    static size_t s1_size() { return 220; }

    static H2Stream* get_stream1() {
        auto *out = new H2Stream();

        auto* h1 = new HeadersFrame();
        h1->len = 31;
        h1->flags = FLAG_END_HEADERS;
        h1->stream_id = 0x00000001;
        h1->add_header(":method", "POST", PrefType::INDEXED_HEADER, IdxType::ALL);
        h1->add_header(":scheme", "https", PrefType::INDEXED_HEADER, IdxType::ALL);
        h1->add_header(":path", "/reqid=4", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NAME);
        h1->add_header(":authority", "localhost:8000", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NAME);

        auto *d1 = new DataFrame();
        d1->len = 8;
        d1->stream_id = 0x00000001;
        const char *data1 = "\x12\x34\x56\x78\x9a\xbc\xde\xf0";
        d1->data.insert(d1->data.end(), data1, data1 + 8);

        auto* d2 = new DataFrame();
        d2->len = 4;
        d2->flags = FLAG_END_STREAM;
        d2->stream_id = 0x00000001;
        const char *data2 = "\xde\xad\xbe\xef";
        d2->data.insert(d2->data.end(), data2, data2+4);

        auto *s = new SettingsFrame;
        s->len = 18;
        s->stream_id = 0x00000001;
        s->add_setting(SETTINGS_ENABLE_PUSH, 0);
        s->add_setting(SETTINGS_INITIAL_WINDOW_SIZE, 0x7fffffff);
        s->add_setting(SETTINGS_HEADER_TABLE_SIZE, 0x0000ffff);

        auto* c = new Continuation();
        c->len = 64;
        c->flags = FLAG_END_HEADERS;
        c->stream_id = 0x00000001;
        c->add_header(":method", "DELETE", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE); // 1 + 2 + 6 = 9
        c->add_header(":path", "/cont_path", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE); // 1 + 2 + 10 = 13
        c->add_header("hdr1", "value1", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE); // 1 + 1 + 4 + 1 + 6 = 13
        c->add_header(":authority", "localhost:10000", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NAME); // 1 + 2 + 15 = 18
        //c->add_header("transfer-encoding", "chunked", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

        auto *pp = new PushPromiseFrame();
        pp->len = 41;
        pp->stream_id = 0x00000001;
        pp->prom_stream_id = 0x10000000;
        pp->add_header("hdr___3", "valueeee", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
        pp->add_header("header_four", "VaLuE", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);

        out->push_back(h1);
        out->push_back(d1);
        out->push_back(d2);
        out->push_back(s);
        out->push_back(c);
        out->push_back(pp);

        return out;
    }

    static H2Stream* get_stream2() {
        auto *out = new H2Stream();

        auto* h1 = new HeadersFrame();
        h1->len = 35;
        h1->flags = FLAG_END_HEADERS;
        h1->stream_id = 0x00000001;
        h1->add_header(":method", "GET", PrefType::INDEXED_HEADER, IdxType::ALL);
        h1->add_header(":scheme", "http", PrefType::INDEXED_HEADER, IdxType::ALL);
        h1->add_header(":path", "/path2", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NAME);
        h1->add_header(":authority", "localhost:9000", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NAME);

        auto *d1 = new DataFrame();
        d1->len = 9;
        d1->stream_id = 0x00000001;
        const char *data1 = "\x9a\xbc\xde\xf0\x00\x12\x34\x56\x78";
        d1->data.insert(d1->data.end(), data1, data1 + 9);

        auto* d2 = new DataFrame();
        d2->len = 5;
        d2->flags = FLAG_END_STREAM;
        d2->stream_id = 0x00000001;
        const char *data2 = "\xbe\xef\x00\xde\xad";
        d2->data.insert(d2->data.end(), data2, data2+5);

        auto *s = new SettingsFrame;
        s->len = 18;
        s->stream_id = 0x00000001;
        s->add_setting(SETTINGS_MAX_CONCURRENT_STREAMS, 0x00000010);
        s->add_setting(SETTINGS_MAX_HEADER_LIST_SIZE, 0xffff0000);
        s->add_setting(SETTINGS_MAX_FRAME_SIZE, 0x12341234);

        auto* c = new Continuation();
        c->len = 66;
        c->flags = FLAG_END_HEADERS;
        c->stream_id = 0x00000001;
        c->add_header(":method", "PUSH", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NAME);
        c->add_header(":path", "/cont_path2", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NAME);
        c->add_header("hdr2", "value2", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
        c->add_header(":authority", "localhost:11000", PrefType::LITERAL_HEADER_WITH_INDEXING, IdxType::NAME);

        auto *pp = new PushPromiseFrame();
        pp->len = 45;
        pp->stream_id = 0x00000001;
        pp->prom_stream_id = 0x10000000;
        pp->add_header("hedder_cinco", "v5lU3", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);
        pp->add_header("6th_header", "eulav", PrefType::LITERAL_HEADER_NEVER_INDEXED, IdxType::NONE);

        out->push_back(h1);
        out->push_back(d1);
        out->push_back(d2);
        out->push_back(s);
        out->push_back(c);
        out->push_back(pp);

        return out;
    }

    static void delete_stream(H2Stream *s) {
        if (s != nullptr) {
            for (auto f: *s) {
                delete f;
            }
            delete s;
        }
    }

    /** Simple mutator function that writes 0x0abcdef001234567 at the beginning the buffer */
    static size_t write_0x0ABCDEF001234567(uint8_t *Data, size_t Size, size_t MaxSize) {
        const char *data = "\x0A\xBC\xDE\xF0\x01\x23\x45\x67";
        for (int i = 0; i < 8 && i < Size; ++i) {
            Data[i] = (uint8_t) data[i];
        }
        return Size;
    }

    /** Simple mutator function that appends "ABCDEFG" to the end of the buffer */
    static size_t rpad_ABCDEFG(uint8_t *Data, size_t Size, size_t MaxSize) {
        const char *data = "ABCDEFG";
        for (int i = 0; i < 7 && Size < MaxSize; ++i) {
            Data[Size] = data[i];
            ++Size;
        }
        return Size;
    }

    static size_t set_padded(uint8_t *Data, size_t Size, size_t MaxSize) {
        *Data |= FLAG_PADDED;
        return Size;
    }

    static size_t set_priority(uint8_t *Data, size_t Size, size_t MaxSize) {
        *Data |= FLAG_PRIORITY;
        return Size;
    }

    /** Simple mutator function that increases the first byte in the buffer by 16 */
    static size_t inc_byte_8(uint8_t *Data, size_t Size, size_t MaxSize) {
        if (Size > 0) {
            Data[0] += 8;
        }
        return Size;
    }

    /** Simple mutator function that increases the first byte in the buffer by 16 */
    static size_t inc_byte_16(uint8_t *Data, size_t Size, size_t MaxSize) {
        if (Size > 0) {
            Data[0] += 16;
        }
        return Size;
    }

    /** Simple mutator function that increases the first byte in the buffer by 128 */
    static size_t inc_byte_128(uint8_t *Data, size_t Size, size_t MaxSize) {
        if (Size > 0) {
            Data[0] += 128;
        }
        return Size;
    }

    /** Simple mutator that subtracts 16 from the first byte in the buffer */
    static size_t dec_byte_16(uint8_t *Data, size_t Size, size_t MaxSize) {
        if (Size > 0) {
            Data[0] -= 16;
        }
        return Size;
    }

    /** Simple mutator function that trims 4 bytes from the end */
    static size_t trim_4(uint8_t *Data, size_t Size, size_t MaxSize) {
        if (Size < 4) {
            return 0;
        }
        return Size - 4;
    }

private:
    std::vector<unsigned int> rands_;
    unsigned int idx_;
};

#endif
