#ifndef H2SRLZ_RST_STREAMFRAME_H
#define H2SRLZ_RST_STREAMFRAME_H

#include "common/baseframe.h"

/*
 *  +---------------------------------------------------------------+
    |                        Error Code (32)                        |
    +---------------------------------------------------------------+
 */
class RstStreamFrame : public Frame {
public:
    uint32_t error_code;

    RstStreamFrame() {
        this->type = RST_STREAM;
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe, bool pres_flags) override {
        this->payload_ = new char[4];
        Utils::uint32_to_buf(this->payload_, this->error_code);
        this->len = 4;
        return serialize_common_(buf, sz);
    }
};

#endif
