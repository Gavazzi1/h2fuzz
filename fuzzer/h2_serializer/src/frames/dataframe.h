#ifndef H2SRLZ_DATAFRAME_H
#define H2SRLZ_DATAFRAME_H

#include "common/baseframe.h"
#include "common/padded.h"

/**
 *  +---------------+
    |Pad Length? (8)|
    +---------------+-----------------------------------------------+
    |                            Data (*)                         ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+
 */
class DataFrame : public Frame, public Padded {
public:
    std::vector<char> data;

    DataFrame() {
        this->type = DATA;
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe=nullptr, bool pres_flags=false) override {
        // temporary buffer for frame-specific fields
        this->payload_ = new char[1 + data.size() + Padded::fields_len_()];
        uint32_t pos = 0;

        // 8-bit pad length
        serialize_padlen_(this->payload_, sz, &pos, this->flags, pres_flags);

        // data
        if (!data.empty()) {
            memcpy(this->payload_ + pos, data.data(), data.size());
            pos += data.size();
        }

        // padding
        serialize_padding_(this->payload_, sz, &pos, this->flags, pres_flags);
        this->len = pos;

        // serialize the entire dataframe
        return serialize_common_(buf, sz);
    }
};

#endif
