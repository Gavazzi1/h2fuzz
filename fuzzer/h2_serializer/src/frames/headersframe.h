#ifndef H2SRLZ_HEADERSFRAME_H
#define H2SRLZ_HEADERSFRAME_H

#include "common/padded.h"
#include "common/depweight.h"
#include "common/headers.h"

using hpack::HPacker;

/**
 *  +---------------+
    |Pad Length? (8)|
    +-+-------------+-----------------------------------------------+
    |E|                 Stream Dependency? (31)                     |
    +-+-------------+-----------------------------------------------+
    |  Weight? (8)  |
    +-+-------------+-----------------------------------------------+
    |                   Header Block Fragment (*)                 ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+
 */
class HeadersFrame : public Frame, public Padded, public DepWeight, public Headers {
public:
    HeadersFrame() {
        this->type = HEADERS;
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe, bool pres_flags) override {
        // temporary buffer for frame-specific fields
        this->payload_ = new char[Padded::fields_len_() + DepWeight::fields_len_() + Headers::fields_len_(hpe)];
        uint32_t pos = 0;

        // 8-bit pad length
        serialize_padlen_(this->payload_, sz, &pos, this->flags, pres_flags);

        if (flags & FLAG_PRIORITY) {
            // 32-bit exclusive flag + stream dependency
            serialize_dep_(this->payload_, sz, &pos);

            // 8-bit weight
            serialize_weight_(this->payload_, sz, &pos);
        }

        // header block fragment
        serialize_headers_(this->payload_, &pos, hpe);

        // padding
        serialize_padding_(this->payload_, sz, &pos, this->flags, pres_flags);

        // serialize the entire dataframe
        this->len = pos;
        return serialize_common_(buf, sz);
    }
};

#endif
