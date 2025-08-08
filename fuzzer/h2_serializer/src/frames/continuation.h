#ifndef H2SRLZ_CONTINUATION_H
#define H2SRLZ_CONTINUATION_H

#include "common/baseframe.h"
#include "common/headers.h"

/*
    +---------------------------------------------------------------+
    |                   Header Block Fragment (*)                 ...
    +---------------------------------------------------------------+
 */
class Continuation : public Frame, public Headers {
public:
    Continuation() {
        this->type = CONTINUATION;
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe, bool pres_flags) override {
        this->payload_ = new char[Headers::fields_len_(hpe)];
        uint32_t pos = 0;

        serialize_headers_(this->payload_, &pos, hpe);

        this->len = pos;
        return serialize_common_(buf, sz);
    }
};

#endif
