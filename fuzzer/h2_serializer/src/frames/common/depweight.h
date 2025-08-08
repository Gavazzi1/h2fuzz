#ifndef H2SRLZ_DEPWEIGHT_H
#define H2SRLZ_DEPWEIGHT_H

#include "utils.h"

class DepWeight {
public:
    bool exclusive = false;
    uint32_t stream_dep = 0;

    uint8_t weight = 0;

protected:
    void serialize_dep_(char* buf, uint32_t sz, uint32_t *pos) {
        char strm_dep_buf[4];
        Utils::uint32_to_buf(strm_dep_buf, this->stream_dep);
        if (this->exclusive) {
            strm_dep_buf[0] |= (char) 0x80;
        }
        memcpy(buf + *pos, strm_dep_buf, 4);
        *pos += 4;
    }

    void serialize_weight_(char* buf, uint32_t sz, uint32_t *pos) {
        memcpy(buf + (*pos)++, &this->weight, 1);
    }

    uint32_t fields_len_() {
        return 5;
    }
};

#endif
