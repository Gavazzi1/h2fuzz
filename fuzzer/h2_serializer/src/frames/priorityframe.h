#ifndef H2SRLZ_PRIORITYFRAME_H
#define H2SRLZ_PRIORITYFRAME_H

#include "common/baseframe.h"
#include "common/depweight.h"

/*
 *  +-+-------------------------------------------------------------+
    |E|                  Stream Dependency (31)                     |
    +-+-------------+-----------------------------------------------+
    |   Weight (8)  |
    +-+-------------+
 */
class PriorityFrame : public Frame, public DepWeight {
public:
    PriorityFrame() {
        this->type = PRIORITY_TYPE;
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe, bool pres_flags) override {
        // temporary buffer for frame-specific fields
        this->payload_ = new char[DepWeight::fields_len_()];
        uint32_t pos = 0;

        // 32-bit exlusive flag + stream dependency
        serialize_dep_(this->payload_, sz, &pos);

        // 8-bit weight
        serialize_weight_(this->payload_, sz, &pos);

        this->len = pos;

        // serialize the entire dataframe
        return serialize_common_(buf, sz);
    }
};

#endif
