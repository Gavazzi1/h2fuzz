#ifndef H2SRLZ_H2STREAM_H
#define H2SRLZ_H2STREAM_H

#include "frames.h"
#include <vector>

class H2Stream : public std::vector<Frame*> {
    using std::vector<Frame*>::vector;

public:
    uint32_t serialize(char *buf, uint32_t sz, bool pres_flags=false) {
        hpack::HPacker hpe;  // shared HPACK context for entire stream
        uint32_t pos = 0;
        for (int i = 0; i < this->size(); ++i) {
            Frame *f = this->at(i);
            pos += f->serialize(buf + pos, sz - pos, &hpe, pres_flags);
        }
        //for (auto f : *this) {
        //    pos += f->serialize(buf + pos, sz - pos, &hpe, pres_flags);
        //}
        return pos;
    }
};

#endif
