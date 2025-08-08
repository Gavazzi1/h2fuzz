#ifndef H2SRLZ_PADDED_H
#define H2SRLZ_PADDED_H

#include "utils.h"
#include <vector>

class Padded {
public:
    // padding optional already in all padded frames, so flags are set to false
    uint8_t padlen = 0;  // pad length field

    std::vector<char> padding;

protected:
    void serialize_padlen_(char* buf, uint32_t sz, uint32_t *pos, uint8_t flags, bool pres_flags=false) {
        // must pass flags here and check PADDED flag explicitly
        // mutator may modify flags, and if PADDED flag is set, we need serialize to respond accordingly
        if (flags & FLAG_PADDED) {
            memcpy(buf + (*pos)++, &padlen, 1);
        }
    }

    void serialize_padding_(char* buf, uint32_t sz, uint32_t *pos, uint8_t flags, bool pres_flags=false) {
        // see comment in serialize_padlen_
        if (flags & FLAG_PADDED && padlen > 0) {
            memcpy(buf + *pos, padding.data(), padlen);
            *pos += padlen;
        }
    }

    uint32_t fields_len_() {
        // padlen + padding + 2 flags
        return 1 + padlen + 2;
    }
};

#endif //H2SRLZ_PADDED_H
