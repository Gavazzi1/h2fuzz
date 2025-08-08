#ifndef H2SRLZ_HEADERS_H
#define H2SRLZ_HEADERS_H

#include "../../hpacker/HPacker.h"

using hpack::HPacker;


class Headers {
public:
    HPacker::KeyValueVector hdr_pairs;
    std::vector<HPacker::PrefixType> prefixes;
    std::vector<HPacker::IndexingType> idx_types;
    int hdr_blk_sz = -1;

    Headers() = default;

    virtual ~Headers() {
        if (this->hdr_srlzd) {
            delete[] this->hdrblk;
        }
    }

    /**
     * Adds a header with the given name and value, to be compressed according to the given prefix and indexing type.
     */
    void add_header(const std::string& name, const std::string &value, HPacker::PrefixType prefix, HPacker::IndexingType idx) {
        this->hdr_pairs.emplace_back(name, value);
        this->prefixes.emplace_back(prefix);
        this->idx_types.emplace_back(idx);
    }

    /**
     * For performance, we try to serialize the headers just once, but in testing, mutators may modify
     * the headers block after the headers have been serialized once, and these modifications will not
     * be reflected in future serializations, as the headers block is cached.
     *
     * This function serves to reset the headers block to enable modification of a headers frame that
     * has been serialized once before.
     */
    void reset_srlz_blk() {
        if (this->hdr_srlzd) {
            delete[] this->hdrblk;
            this->hdr_srlzd = false;
        }
    }

protected:
    void serialize_headers_(char* buf, uint32_t *pos, HPacker *hpe) {
        if (!hdr_srlzd) {
            do_srlz(hpe);
        }

        memcpy(buf + *pos, this->hdrblk, this->hdr_blk_sz);
        DEBUG("header block of size " << hdr_blk_sz << " copied into buffer")
        *pos += hdr_blk_sz;
    }

    uint32_t fields_len_(HPacker *hpe) {
        if (!hdr_srlzd) {
            do_srlz(hpe);
        }
        return this->hdr_blk_sz;
    }

private:
    void do_srlz(HPacker *hpe) {
        this->hdrblk = new uint8_t[4096];
        if (!this->hdr_pairs.empty()) {
            hdr_blk_sz = hpe->encode(hdr_pairs, hdrblk, 4096, prefixes, idx_types);
            if (hdr_blk_sz == -1) {
                delete [] this->hdrblk;
                throw std::runtime_error("Error encoding HPACK body");
            }
        }
        else {
            DEBUG("serializing empty headers block")
            hdr_blk_sz = 0;
        }
        
        DEBUG("headers serialized in block of size " << hdr_blk_sz)
        hdr_srlzd = true;
    }

    bool hdr_srlzd = false;
    uint8_t *hdrblk = nullptr;
};

#endif
