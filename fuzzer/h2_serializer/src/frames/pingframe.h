#ifndef H2SRLZ_PINGFRAME_H
#define H2SRLZ_PINGFRAME_H

#include "common/baseframe.h"
#include "common/utils.h"

/*
 *  +---------------------------------------------------------------+
    |                                                               |
    |                      Opaque Data (64)                         |
    |                                                               |
    +---------------------------------------------------------------+
 */
class PingFrame : public Frame {
public:
    uint64_t data = 0;

    PingFrame() {
        this->type = PING;
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe, bool pres_flags) override {
        this->payload_ = new char[8];
        Utils::uint64_to_buf(this->payload_, this->data);
        this->len = 8;
        return serialize_common_(buf, sz);
    }
};

#endif
