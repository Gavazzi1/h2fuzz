#ifndef H2SRLZ_PUSH_PROMISEFRAME_H
#define H2SRLZ_PUSH_PROMISEFRAME_H

#include "common/baseframe.h"
#include "common/padded.h"
#include "common/headers.h"

/*
    +---------------+
    |Pad Length? (8)|
    +-+-------------+-----------------------------------------------+
    |R|                  Promised Stream ID (31)                    |
    +-+-----------------------------+-------------------------------+
    |                   Header Block Fragment (*)                 ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+
 */
class PushPromiseFrame : public Frame, public Padded, public Headers {
public:
    bool reserved_pp = false;
    uint32_t prom_stream_id = 0x00000000;

    PushPromiseFrame() {
        this->type = PUSH_PROMISE;
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe, bool pres_flags) override {
        this->payload_ = new char[4 + Padded::fields_len_() + Headers::fields_len_(hpe)];
        uint32_t pos = 0;

        // 8-bit pad length
        serialize_padlen_(this->payload_, sz, &pos, this->flags, pres_flags);

        // reserved bit and promised stream ID
        uint32_t r_sid = prom_stream_id;
        r_sid |= reserved_pp ? 0x80000000 : 0x00000000;
        Utils::uint32_to_buf(this->payload_+pos, r_sid);
        pos += 4;

        // header block
        serialize_headers_(this->payload_, &pos, hpe);

        // padding
        serialize_padding_(this->payload_, sz, &pos, this->flags, pres_flags);

        // serialize the entire dataframe
        this->len = pos;
        return serialize_common_(buf, sz);
    }
};

#endif
