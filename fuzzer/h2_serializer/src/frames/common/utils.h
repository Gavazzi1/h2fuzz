#ifndef H2SRLZ_UTILS_H
#define H2SRLZ_UTILS_H

#include <cstdint>
#include <cstring>
#include <cstdio>


class Utils {
public:
    // constants for copying booleans into buffer
    static const uint8_t one_;
    static const uint8_t zero_;

    static void uint16_to_buf(char* buf, uint16_t val) {
        buf[0] = (char) ((val >>  8) & 0xff);
        buf[1] = (char) ((val >>  0) & 0xff);
    }

    static uint16_t buf_to_uint16(char* buf) {
        return (((uint8_t) buf[0]) << 8) + (uint8_t)buf[1];
    }

    static void uint32_to_buf(char* buf, uint32_t val) {
        buf[0] = (char) ((val >> 24) & 0xff);
        buf[1] = (char) ((val >> 16) & 0xff);
        buf[2] = (char) ((val >>  8) & 0xff);
        buf[3] = (char) ((val >>  0) & 0xff);
    }

    static uint32_t buf_to_uint32(const char* buf) {
        uint32_t val = 0;
        for (int i = 0; i < 4; ++i) {
            val = (val<<8) + (uint8_t)buf[i];
        }

        return val;
    }

    static void uint64_to_buf(char* buf, uint64_t val) {
        buf[0] = (char) ((val >> 56) & 0xff);
        buf[1] = (char) ((val >> 48) & 0xff);
        buf[2] = (char) ((val >> 40) & 0xff);
        buf[3] = (char) ((val >> 32) & 0xff);
        buf[4] = (char) ((val >> 24) & 0xff);
        buf[5] = (char) ((val >> 16) & 0xff);
        buf[6] = (char) ((val >>  8) & 0xff);
        buf[7] = (char) ((val >>  0) & 0xff);
    }

    static uint64_t buf_to_uint64(const char* buf) {
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val = (val<<8) + (uint8_t)buf[i];
        }

        return val;
    }

    /*
     * Returns a dynamically-allocated char array of the given const char array of the given size
     */
    static char* dynamic_char_arr(const char *in, uint32_t insz) {
        char* out = new char[insz];
        for (int i = 0; i < insz; ++i) {
            out[i] = in[i];
        }
        return out;
    }

    static void prnt(char* buf, uint32_t sz) {
        for (int i = 0; i < sz; ++i) {
            printf("\\x%x", (uint8_t) buf[i]);
        }
        printf("\n");
    }
};


#endif
