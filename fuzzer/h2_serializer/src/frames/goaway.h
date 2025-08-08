#ifndef H2SRLZ_GOAWAY_H
#define H2SRLZ_GOAWAY_H

#include "common/baseframe.h"
#include "common/utils.h"

/*
 *  +-+-------------------------------------------------------------+
    |R|                  Last-Stream-ID (31)                        |
    +-+-------------------------------------------------------------+
    |                      Error Code (32)                          |
    +---------------------------------------------------------------+
    |                  Additional Debug Data (*)                    |
    +---------------------------------------------------------------+
 */
class GoAway : public Frame {
public:
    bool reserved_ga = false;
    uint32_t last_stream_id = 0;
    uint32_t error_code = 0;
    std::vector<char> debug_data;

    GoAway() {
        this->type = GOAWAY;
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe, bool pres_flags) override {
        this->payload_ = new char[4 + 4 + this->debug_data.size()];
        uint32_t pos = 0;

        // Reserved bit and last stream ID
        uint32_t r_sid = this->last_stream_id;
        r_sid |= reserved_ga ? 0x80000000 : 0x00000000;
        Utils::uint32_to_buf(this->payload_, r_sid);
        pos += 4;

        // Error code
        Utils::uint32_to_buf(this->payload_+pos, this->error_code);
        pos += 4;

        // Additional Debug data
        memcpy(this->payload_+pos, this->debug_data.data(), this->debug_data.size());
        pos += this->debug_data.size();

        this->len = pos;
        return serialize_common_(buf, sz);
    }
};

#endif
