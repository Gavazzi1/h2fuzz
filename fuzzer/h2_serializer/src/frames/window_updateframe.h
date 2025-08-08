#ifndef H2SRLZ_WINDOW_UPDATEFRAME_H
#define H2SRLZ_WINDOW_UPDATEFRAME_H

#include "common/baseframe.h"
#include "common/utils.h"

/*
    +-+-------------------------------------------------------------+
    |R|              Window Size Increment (31)                     |
    +-+-------------------------------------------------------------+
 */
class WindowUpdate : public Frame {
public:
    bool reserved_wu = false;
    uint32_t win_sz_inc = 0;

    WindowUpdate() {
        this->type = WINDOW_UPDATE;
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe, bool pres_flags) override {
        this->payload_ = new char[4];

        uint32_t r_wsi = this->win_sz_inc;
        r_wsi |= this->reserved_wu ? 0x80000000 : 0x00000000;
        Utils::uint32_to_buf(this->payload_, r_wsi);

        this->len = 4;
        return serialize_common_(buf, sz);
    }
};

#endif
