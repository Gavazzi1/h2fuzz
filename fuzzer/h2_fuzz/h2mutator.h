#ifndef H2SRLZ_H2MUTATOR_H
#define H2SRLZ_H2MUTATOR_H

#include <iostream>
#include <random>
#include <climits>
#include <algorithm>
#include <set>
#include <cassert>
#include "../h2_serializer/src/deserializer.h"
#include "../h2_serializer/src/frame_copier.h"
#include "../h2_serializer/src/hpacker/HPacker.h"
#include "../h2_serializer/src/hpacker/StaticTable.h"
#include "h2fuzzconfig.h"
#include "../debug.h"
#include "proxy_config.h"
#include "util.h"

typedef hpack::HPacker::PrefixType PrefType;
typedef hpack::HPacker::IndexingType IdxType;

// Mutate() operations
#define N_MUT_OPS 4
#define BIT 0
#define DELETE 1
#define DUP 2
#define SWAP 3
#define FIX 4

// CrossOver() operations
#define N_CROSS_OPS 2
#define ADD 0
#define SPLICE 1

class H2Mutator {
public:
    H2FuzzConfig cfg_;

    uint64_t size() const {
        return strm_sz_;
    }

    explicit H2Mutator(std::istream &in) {
        parse_stream(in);
    }

    H2Mutator(std::istream &in, const std::string &fn) {
        parse_stream(in);
        cfg_.read_config(fn);
    }

    H2Mutator(char *buf, size_t sz) {
        membuf sbuf(buf, buf + sz);
        std::istream strm(&sbuf);
        parse_stream(strm);
    }

    H2Mutator(char *buf, size_t sz, const std::string &fn) {
        membuf sbuf(buf, buf + sz);
        std::istream strm(&sbuf);
        parse_stream(strm);
        cfg_.read_config(fn);
    }

    virtual ~H2Mutator() {
        if (strm_ != nullptr) {
            for (Frame *f: *strm_) {
                delete f;
            }
            delete strm_;
        }
    }

    /**
     * Returns the number of bytes needed to encode the given integer using HPACK integer encoding with a prefix of 7
     */
    static int hpack_int_length(uint64_t I, uint8_t N = 7) {
        uint8_t NF = (1 << N) - 1;
        if (I < NF) { return 1; }
        int out = 1;
        I -= NF;
        while (I >= 128) {
            ++out;
            I /= 128;
        }
        ++out;
        return out;
    }

    /**
     * For each header in the given Frame, scan through every subsequent frame in this stream and update the encodings
     * of any headers that would not be encoded correctly if the current header were to be deleted.
     * @param f the Frame (with headers) that will be deleted
     * @param idx f's position in the current HTTP/2 stream
     */
    void post_patch_header_deletion(Frame *f, unsigned int idx) {
        auto h = dynamic_cast<Headers *>(f); // guaranteed not to be nullptr
        assert(h != nullptr); // but assert just in case
        assert(idx < this->strm_->size() - 1);
        Frame *next_f = this->strm_->at(idx + 1);

        // get set of all available headers in Frames prior to this one
        std::set<HPacker::KeyValuePair> nv_pairs;
        std::set<std::string> names;
        headers_in_table(nv_pairs, names, f, 0);

        for (int i = 0; i < h->hdr_pairs.size(); ++i) {
            // if this header is added to the dynamic table and is NOT already in the table, we need to check dependencies
            if (h->prefixes[i] == PrefType::LITERAL_HEADER_WITH_INDEXING && !set_contains(nv_pairs, h->hdr_pairs[i])) {
                // don't actually care about modifying encodings of headers in this frame since they will be deleted
                // pass next_f so that we start scanning on the frame after this one
                // pass -1 as idx so that the starting index will be 0 (hacky, but it works)
                post_patch_header_encodings(next_f, -1, h->hdr_pairs[i], set_contains(names, h->hdr_pairs[i].first));
            }
        }
    }


    // Raw byte array mutator, like that provided by libFuzzer.
    using Mutator = size_t (*)(uint8_t *Data, size_t Size, size_t MaxSize);

    /**
     * Mutate the in-memory representation of an HTTP/2 stream
     * Given the same Seed, the same mutation is performed.
     * Mutation are bit-level, Frame/header deletion, Frame/header duplication, and Frame/header swapping
     *
     * Returns 1 if the mutation was successful, 0 otherwise
     */
    size_t Mutate(Mutator m, unsigned int Seed, unsigned int MaxSize) {
        DEBUG("Mutate")
        std::minstd_rand rnd(Seed);
        this->rnd_ = &rnd;

        if (strm_ == nullptr || strm_->empty()) {
            DEBUG("null or empty stream. returning")
            return 0;
        }

        // pick frame to mutate
        unsigned int pos1 = my_rand(strm_->size());
        Frame *f1, *f2;
        f1 = strm_->at(pos1);

        unsigned int op = get_mut_op();
        switch (op) {
            case BIT:
                DEBUG("bit mutation")
                return bit_mutation(f1, m, MaxSize);
            case DELETE:
                DEBUG("delete frame mutation")
                // if there are frames after this one and this frame has headers, update header encoding dependencies
                if (pos1 < strm_->size() - 1 && Frame::has_headers(f1)) {
                    post_patch_header_deletion(f1, pos1);
                }
                strm_->erase(strm_->begin() + pos1);
                strm_sz_ -= HDRSZ + f1->len;
                delete f1;
                return 1;
            case DUP:
                DEBUG("duplicate frame mutation")
                // check bounds first
                if (strm_sz_ + f1->len + HDRSZ > MaxSize) {
                    DEBUG("no room to duplicate frame. returning")
                    return 0;
                }

                f2 = FrameCopier::copy_frame(f1);
                DEBUG("duplicating frame index " << pos1 << " of type " << (int) f1->type)
                strm_->insert(strm_->begin() + pos1, f2);
                strm_sz_ += f2->len + HDRSZ;
                return 1;
            case SWAP:
                return swap_frames(pos1, MaxSize);
            case FIX:
                return fix_flags();
            default:
                std::cout << "Invalid operation in Mutate: " << op << std::endl;
                return 0;
        }
    }

    /**
     * "Fixes" the current stream such that ONLY the last frame has the END_STREAM flag set and ONLY the last
     * frame containing headers has the END_HEADERS flag set.
     *
     * Update: Reviewing the RFC, only DATA and HEADERS frames support the END_STREAM flag. Testing this
     */
    size_t fix_flags() {
        bool set_ES = false;
        bool set_EH = false;
        for (long i = strm_->size() - 1; i >= 0; --i) {
            uint8_t ftype = strm_->at(i)->type;
            if (!set_ES and (ftype == DATA or ftype == HEADERS)) {
                strm_->at(i)->flags |= FLAG_END_STREAM;
                set_ES = true;
            } else {
                strm_->at(i)->flags &= ~FLAG_END_STREAM;
            }

            if (Frame::has_headers(strm_->at(i))) {
                if (!set_EH) {
                    strm_->at(i)->flags |= FLAG_END_HEADERS;
                    set_EH = true;
                } else {
                    strm_->at(i)->flags &= ~FLAG_END_HEADERS;
                }
            }
        }

        return strm_sz_;
    }

    /**
     * Actual implementation of swap frames, which swaps the frames at idx_sm and idx_log,
     * with the requirement that idx_sm <= idx_lg
     */
    size_t swap_frames_impl_(unsigned int idx_sm, unsigned int idx_lg, unsigned int MaxSize) {
        Frame *f_sm = strm_->at(idx_sm);
        Frame *f_lg = strm_->at(idx_lg);

        // from swap_headers, max possible size increase from a swap is a header size
        // thus, max possible increase here is the sum of all headers in this frame
        // huge overestimation, but time required to get it right vs payoff ratio not good...
        unsigned int sz_update = 0;
        if (Frame::has_headers(f_sm)) {
            for (auto hdr: dynamic_cast<Headers *>(f_sm)->hdr_pairs) {
                sz_update += hdr_sz(&hdr);
            }
        }
        if (Frame::has_headers(f_lg)) {
            for (auto hdr: dynamic_cast<Headers *>(f_lg)->hdr_pairs) {
                sz_update += hdr_sz(&hdr);
            }
        }
        if (strm_sz_ + sz_update > MaxSize) { return 0; }

        std::set<HPacker::KeyValuePair> nv_pairs;
        std::set<std::string> names;
        headers_in_table(nv_pairs, names, f_sm, 0);

        // if frame at low index has headers, must update header encodings in all frames between idx_sm and idx_lg
        if (Frame::has_headers(f_sm)) {
            auto h = dynamic_cast<Headers *>(f_sm);
            for (int i = 0; i < h->hdr_pairs.size(); ++i) {
                HPacker::KeyValuePair hdr = h->hdr_pairs[i];
                if (h->prefixes[i] == PrefType::LITERAL_HEADER_WITH_INDEXING && !set_contains(nv_pairs, hdr)) {
                    // patch starting at frame at index after idx_sm, patch every header, and only scan up to frame at idx_lg-1
                    post_patch_header_encodings(this->strm_->at(idx_sm + 1), -1, h->hdr_pairs[i],
                                                set_contains(names, hdr.first),
                                                false, -1, idx_lg - 1);
                }
            }
        }

        // if frame at high index has headers, must update encodings based on whether headers are available before
        // the frame at idx_sm
        if (Frame::has_headers(f_lg)) {
            auto h = dynamic_cast<Headers *>(f_lg);
            for (int i = 0; i < h->hdr_pairs.size(); ++i) {
                if (h->idx_types[i] == IdxType::NONE ||
                    set_contains(nv_pairs, h->hdr_pairs[i]) ||
                    (h->idx_types[i] == IdxType::NAME && set_contains(names, h->hdr_pairs[i].first))) {
                    continue;
                }
                h->prefixes[i] = PrefType::LITERAL_HEADER_WITH_INDEXING;
                h->idx_types[i] = set_contains(names, h->hdr_pairs[i].first) ? IdxType::NAME : IdxType::NONE;
            }
        }

        // perform swap
        std::iter_swap(strm_->begin() + idx_sm, strm_->begin() + idx_lg);
        return 1;
    }

    size_t swap_frames(unsigned int idx1, unsigned int MaxSize) {
        DEBUG("swap frame mutation")
        unsigned int idx2 = my_rand(this->strm_->size());

        unsigned int idx_sm = std::min(idx1, idx2);
        unsigned int idx_lg = std::max(idx1, idx2);
        if (idx_sm == idx_lg) {
            return 0;
        }
        return swap_frames_impl_(idx_sm, idx_lg, MaxSize);
    }

    /**
     * Performs crossover mutations between the given HTTP/2 stream mutator and this one
     * Given the same Seed, the same mutation is performed.
     * Mutation operations are addition and splicing (replacement) of headers and frames
     */
    size_t CrossOver(const H2Mutator &p, unsigned int Seed, unsigned int MaxSize) {
        DEBUG("CrossOver")
        std::minstd_rand rnd(Seed);
        this->rnd_ = &rnd;

        if (strm_ == nullptr || p.strm_ == nullptr || p.strm_->empty()) {
            return 0;
        }

        unsigned int this_idx, other_idx, op;

        // check whether Settings/Header crossover is possible
        if (!this->strm_->empty()) {
            this_idx = my_rand(this->strm_->size());
            Frame *this_frm = this->strm_->at(this_idx);

            other_idx = my_rand(p.strm_->size());
            Frame *other_frm = p.strm_->at(other_idx);

            bool bothsettings = this_frm->type == SETTINGS && other_frm->type == SETTINGS;
            bool bothheaders = Frame::has_headers(this_frm) && Frame::has_headers(other_frm);
            if ((bothsettings || bothheaders) && header_mut_rand()) {
                if (bothheaders) {
                    return cross_over_headers(this_frm, other_frm, MaxSize);
                } else {
                    auto this_settings = &dynamic_cast<SettingsFrame *>(this_frm)->settings;
                    auto other_settings = &dynamic_cast<SettingsFrame *>(other_frm)->settings;
                    Setting s;
                    return cross_over_impl(this_settings, other_settings, MaxSize,
                                           H2Mutator::setting_sz, H2Mutator::setting_cpy,
                                           &s, this_idx, other_idx, op);
                }
            }
        }

        return cross_over_frames(this->strm_, p.strm_, MaxSize);
    }

    H2Stream *strm_ = nullptr;  // HTTP/2 stream to be mutated

protected:
    void parse_stream(std::istream &in) {
        try {
            strm_ = Deserializer::deserialize_stream(in);
            strm_sz_ = 0;
            for (auto f: *strm_) {
                strm_sz_ += HDRSZ + f->len;
            }
        } catch (...) {
            std::cout << "Mutator: could not parse stream" << std::endl;
            strm_ = nullptr;
            strm_sz_ = 0;
        }
    }

    /** Wrapper for generating a random unsigned integer in the range [0, mod) */
    virtual unsigned int my_rand(unsigned int mod) {
        return (*this->rnd_)() % mod;
    }

    virtual unsigned int get_mut_op() {
        unsigned int score = my_rand(100);
        unsigned int acc = cfg_.prob_swap;

        if (score < acc) return SWAP;
        acc += cfg_.prob_dup;
        if (score < acc) return DUP;
        acc += cfg_.prob_delete;
        if (score < acc) return DELETE;
        acc += cfg_.prob_fix;
        if (score < acc) return FIX;
        return BIT;  // default to bit mutations if config hasn't been loaded
    }

    virtual unsigned int get_cross_op() {
        if (my_rand(100) < cfg_.prob_add) return ADD;
        return SPLICE;
    }

    virtual bool header_mut_rand() {
        return my_rand(100) < cfg_.prob_do_hdr_set_mut;
    }

    /** Sets pref and idx_type to the closest valid encoding of the prefix and indexing type of the header at index
     * "idx" within "h" given sets of available names and name/value pairs in the table.
     */
    void patch_one_header_encoding(Headers *h, unsigned int idx,
                                   const std::set<HPacker::KeyValuePair> &nv_pairs, const std::set<std::string> &names,
                                   PrefType &pref, IdxType &idx_type) {
        pref = h->prefixes[idx];
        idx_type = h->idx_types[idx];
        if (idx_type == IdxType::ALL && !set_contains(nv_pairs, h->hdr_pairs[idx])) {
            pref = PrefType::LITERAL_HEADER_WITH_INDEXING; // always add to table
            idx_type = set_contains(names, h->hdr_pairs[idx].first) ? IdxType::NAME : IdxType::NONE;
        } else if (idx_type == IdxType::NAME && !set_contains(names, h->hdr_pairs[idx].first)) {
            idx_type = IdxType::NONE;
        }
    }

    /**
     * Performs a CrossOver operation on two Frames with headers. Must be implemented separately from
     * Settings and Frames because we must resolve header encoding dependencies.
     */
    bool cross_over_headers(Frame *this_f, Frame *other_f, unsigned int MaxSize) {
        auto this_h = dynamic_cast<Headers *>(this_f);
        auto other_h = dynamic_cast<Headers *>(other_f);

        if (other_h->hdr_pairs.empty()) {
            return false;
        }

        unsigned int this_idx, other_idx = my_rand(other_h->hdr_pairs.size());
        HPacker::KeyValuePair other_hdr = other_h->hdr_pairs[other_idx];

        // adding header at worst adds the full literal header -- at best 1 byte
        // splicing header adds at worst the full literal header. orig header is deleted, which at worst decreases
        // the total size by 1 byte, at best decreases by full literal header size
        if (strm_sz_ + hdr_sz(&other_hdr) > MaxSize) {
            return false;
        }

        // pick a CrossOver operation and pick the index to perform the operation at
        unsigned int op = get_cross_op();
        if (op == ADD) {
            this_idx = my_rand(this_h->hdr_pairs.size() + 1);
        } else if (op == SPLICE) {
            if (this_h->hdr_pairs.empty()) { return false; }
            this_idx = my_rand(this_h->hdr_pairs.size());
        } else {
            throw std::runtime_error("Invalid CrossOver operation");
        }

        // get headers in table up to the header at the index we are inserting at, as well as the header itself
        std::set<HPacker::KeyValuePair> nv_pairs;
        std::set<std::string> names;
        headers_in_table(nv_pairs, names, this_f, this_idx);

        // compute the prefix and indexing type of the header being added
        PrefType pref;
        IdxType idx_type;
        patch_one_header_encoding(other_h, other_idx, nv_pairs, names, pref, idx_type);

        // now perform the actual header crossover, then update prefixes and indexing types
        if (op == ADD) {
            this_h->hdr_pairs.insert(this_h->hdr_pairs.begin() + this_idx, other_hdr);
            this_h->prefixes.insert(this_h->prefixes.begin() + this_idx, pref);
            this_h->idx_types.insert(this_h->idx_types.begin() + this_idx, idx_type);
        } else if (op == SPLICE) {
            HPacker::KeyValuePair this_hdr = this_h->hdr_pairs[this_idx];

            // update future header encodings that may depend on the header being spliced out
            if (!set_contains(nv_pairs, this_hdr) &&
                this_h->prefixes[this_idx] == PrefType::LITERAL_HEADER_WITH_INDEXING) {
                post_patch_header_encodings(this_f, this_idx, this_hdr, set_contains(names, this_hdr.first));
            }

            // subtract the size of the header we replace
            strm_sz_ -= hdr_sz(&this_hdr, this_h->idx_types[this_idx]);
            this_f->len -= hdr_sz(&this_hdr, this_h->idx_types[this_idx]);

            this_h->hdr_pairs[this_idx] = other_hdr;
            this_h->prefixes[this_idx] = pref;
            this_h->idx_types[this_idx] = idx_type;
        } else {
            throw std::runtime_error("Invalid CrossOver operation");
        }

        // lastly, increase stream size by the newly added header
        strm_sz_ += hdr_sz(&other_hdr, idx_type);
        this_f->len += hdr_sz(&other_hdr, idx_type);
        return true;
    }

    /**
     * Performs a crossover operation among Frames in a Stream, updating header encodings where necessary.
     */
    bool cross_over_frames(H2Stream *this_s, H2Stream *other_s, unsigned int MaxSize) {
        if (other_s->empty()) { return false; }

        // pick a random frame from other_s and copy it
        Frame *other_f = FrameCopier::copy_frame(other_s->at(my_rand(other_s->size())));
        Headers *other_h;

        // compute max size increase by adding/splicing other_f, then terminate early if it exceeds MaxSize
        // TODO: definitely a bug here. don't consider padding or depweight in HeadersFrame, or padding in PushPromise
        int64_t max_sz_inc = HDRSZ + other_f->len;
        if (Frame::has_headers(other_f)) {
            //max_sz_inc -= other_f->len;

            other_h = dynamic_cast<Headers *>(other_f);
            max_sz_inc -= other_h->hdr_blk_sz;
            for (auto hdr: other_h->hdr_pairs) {
                max_sz_inc += (int64_t) hdr_sz(&hdr);
            }
        }

        // pick a crossover operation and then pick an index in this stream
        unsigned int this_idx, op = get_cross_op();
        if (op == ADD) {
            this_idx = my_rand(this_s->size() + 1);
        } else if (op == SPLICE) {
            if (this_s->empty()) {
                delete other_f;
                return false;
            }
            this_idx = my_rand(this_s->size());

            // if we are overwriting a non-headers frame, guaranteed to decrease size of stream by that frame's size
            if (!Frame::has_headers(this_s->at(this_idx))) {
                max_sz_inc -= HDRSZ + this_s->at(this_idx)->len;
            }
        } else {
            throw std::runtime_error("Invalid CrossOver operation");
        }

        if ((int64_t) strm_sz_ + max_sz_inc > MaxSize) {
            delete other_f;
            return false;
        }

        // get headers in table up to the Frame at this_idx
        std::set<HPacker::KeyValuePair> nv_pairs;
        std::set<std::string> names;
        if (this_idx < this_s->size()) {
            headers_in_table(nv_pairs, names, this_s->at(this_idx), 0);
        } else {
            headers_in_table(nv_pairs, names, nullptr, 0);
        }

        // if frame to be added has headers, update all encodings to be valid based on headers in table
        if (Frame::has_headers(other_f)) {
            for (int i = 0; i < other_h->hdr_pairs.size(); ++i) {
                PrefType pref;
                IdxType idx_type;
                patch_one_header_encoding(other_h, i, nv_pairs, names, pref, idx_type);
                other_h->prefixes[i] = pref;
                other_h->idx_types[i] = idx_type;

                // if we add this header, update nv_pairs and names
                if (pref == PrefType::LITERAL_HEADER_WITH_INDEXING) {
                    nv_pairs.insert(other_h->hdr_pairs[i]);
                    names.insert(other_h->hdr_pairs[i].first);
                }
            }
        }

        if (op == ADD) {
            this_s->insert(this_s->begin() + this_idx, other_f);
        } else if (op == SPLICE) {
            Frame *this_f = this_s->at(this_idx);
            // for splice, check dependencies from any headers that followed the one being deleted
            // but only if there are any frames that follow this one
            if (this_idx < this_s->size() - 1 && Frame::has_headers(this_f)) {
                post_patch_header_deletion(this_f, this_idx);
            }

            strm_sz_ -= HDRSZ + this_f->len;
            delete this_f;
            this_s->at(this_idx) = other_f;
        } else {
            throw std::runtime_error("Invalid CrossOver operation");
        }

        strm_sz_ += HDRSZ + other_f->len;
        if (Frame::has_headers(other_f)) {
            strm_sz_ -= other_f->len;
            for (int i = 0; i < other_h->hdr_pairs.size(); ++i) {
                strm_sz_ += hdr_sz(&other_h->hdr_pairs[i], other_h->idx_types[i]);
            }
        }
        return true;
    }

    /**
     * Templatized helper function to abstract CrossOver logic for arbitrary vectors. Supports Frame, Header, and Settings
     * @param mut the container to mutate
     * @param other the container to cross over with
     * @param MaxSize maximum size of serialized stream
     * @param sz_func function that returns the size of a T in the serialized buffer
     * @param copier function that returns a new copy of a given T
     * @param orig T pointer used for passing the removed element in SPLICE so that it can be deleted, when necessary
     */
    template<class T>
    bool cross_over_impl(std::vector<T> *mut, std::vector<T> *other, unsigned int MaxSize, size_t (*sz_func)(T *),
                         T (*copier)(T), T *orig,
                         unsigned int &this_idx, unsigned int &other_idx, unsigned int &op) {
        if (other->empty()) {
            return false;
        }

        unsigned int newsz;
        T this_el, other_el;

        other_idx = my_rand(other->size());
        other_el = copier(other->at(other_idx));
        op = get_cross_op();
        DEBUG("operator: " << op)

        switch (op) {
            case ADD:
                this_idx = my_rand(mut->size() + 1);

                // check bounds
                newsz = strm_sz_ + sz_func(&other_el);
                if (newsz > MaxSize) {
                    *orig = other_el;
                    return false;
                }

                mut->insert(mut->begin() + this_idx, other_el);
                strm_sz_ = newsz;
                break;
            case SPLICE:
                if (mut->empty()) {
                    return false; // can't perform operation if there are no frames
                }

                this_idx = my_rand(mut->size());
                this_el = mut->at(this_idx);

                newsz = strm_sz_ - sz_func(&this_el) + sz_func(&other_el);
                if (newsz > MaxSize) {
                    *orig = other_el;
                    return false;
                }

                mut->at(this_idx) = other_el;
                strm_sz_ = newsz;
                *orig = this_el;
                break;
            default:
                std::cout << "Invalid operation in CrossOver: " << op << std::endl;
        }
        return true;
    }

    /**
     * Returns the maximum possible size of the given header. That is, its size if its name and value are literals
     */
    static size_t hdr_sz(HPacker::KeyValuePair *hdr) {
        return 1 +
               hpack_int_length(hdr->first.size()) + hdr->first.size() +
               hpack_int_length(hdr->second.size()) + hdr->second.size();
    }

    /**
     * Returns the exact size of the given header with the given indexing type
     */
    static size_t hdr_sz(HPacker::KeyValuePair *hdr, HPacker::IndexingType idx_type) {
        switch (idx_type) {
            case HPacker::IndexingType::NONE:
                return hdr_sz(hdr);
            case HPacker::IndexingType::NAME:
                return 2 + hpack_int_length(hdr->second.size()) + hdr->second.size();
            case HPacker::IndexingType::ALL:
                return 1;
            case HPacker::IndexingType::OTHER:
                throw std::runtime_error("Undefined header size for indexing type OTHER");
        }
    }

    /** Returns a copy of the given header */
    static HPacker::KeyValuePair hdr_cpy(HPacker::KeyValuePair hdr) {
        return hdr;
    }

    /** Returns the size of the given Setting */
    static size_t setting_sz(Setting *s) {
        return sizeof(s->first) + sizeof(s->second);
    }

    /** Returns a copy of the given Setting */
    static Setting setting_cpy(Setting s) {
        return s;
    };

    /** Returns the size of the given Frame */
    static size_t frame_sz(Frame **f) {
        return HDRSZ + (*f)->len;
    }

    virtual size_t do_field_mutation(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        switch (fr.frametype) {
            case DATA:
                return mutate_dataframe(fr, f, m, MaxSize);
            case HEADERS:
                return mutate_headersframe(fr, f, m, MaxSize);
            case PRIORITY_TYPE:
                return mutate_priorityframe(fr, f, m, MaxSize);
            case RST_STREAM:
                return mutate_rst_streamframe(fr, f, m, MaxSize);
            case SETTINGS:
                return mutate_settingsframe(fr, f, m, MaxSize);
            case PUSH_PROMISE:
                return mutate_push_promiseframe(fr, f, m, MaxSize);
            case PING:
                return mutate_pingframe(fr, f, m, MaxSize);
            case GOAWAY:
                return mutate_goaway(fr, f, m, MaxSize);
            case WINDOW_UPDATE:
                return mutate_window_updateframe(fr, f, m, MaxSize);
            case CONTINUATION:
                return mutate_continuation(fr, f, m, MaxSize);
            case BASE:
                return mutate_baseframe(fr, f, m, MaxSize);
            case DEPWEIGHT:
                return mutate_depweight(fr, f, m, MaxSize);
            case HDRS:
                return mutate_headers(fr, f, m, MaxSize);
            case PAD:
                return mutate_padded(fr, f, m, MaxSize);
            default:
                std::cout << "Mutator: Unknown frame type: " << fr.frametype << std::endl;
                return 0;
        }
    }

    /**
     * Performs structure-aware bit mutations on the given Frame
     * @param f Frame to mutate
     * @param m in-built Mutator function
     * @param MaxSize maximum allowed size of the output
     */
    virtual size_t bit_mutation(Frame *f, Mutator m, unsigned int MaxSize) {
        std::vector<FieldRep> *fields = cfg_.get_fields(f->type);
        if (fields == nullptr || fields->empty()) {
            std::cout << "No mutable fields found for frame: " << (int) f->type << std::endl;
            return 0;
        }
        unsigned int f_idx = my_rand(fields->size());
        DEBUG("Bit mutation on field " << f_idx << " of frame " << (int) f->type)
        FieldRep fr = fields->at(f_idx);
        return do_field_mutation(fr, f, m, MaxSize);
    }

    /**
     * Mutates a vector<char> representing a mutable buffer that can be grown or shrunken
     *
     * returns 1 if the mutation is successful, 0 otherwise
     * */
    size_t mutate_vector_(std::vector<char> *data, Frame *f, unsigned int allowed_size, Mutator m) {
        assert(allowed_size >= data->size());
        uint8_t databuf[allowed_size];
        memcpy(databuf, data->data(), data->size());

        // mutate
        size_t newsz = m(databuf, data->size(), allowed_size);

        // check error case, unless data was small enough that 0 might be a valid response (e.g., MutationDispatcher::Mutate_EraseByte)
        if (newsz == 0 && data->size() > 1) {
            return 0;
        }

        // SIZE_MAX is the signal from Mutate_ClearField
        if (newsz == SIZE_MAX) {
            newsz = 0;
        }

        // update meta variables and copy back into buffer
        f->len = f->len + newsz - data->size();
        strm_sz_ = strm_sz_ + newsz - data->size();
        data->assign((char *) databuf, (char *) databuf + newsz);
        return 1;
    }

    /**
     * Helper method to abstract logic of mutating a string from mutate_headers()
     *
     * NOTE: unlike mutate_vector, the size of the frame in which the string resides is NOT updated here
     */
    static size_t mutate_string_(std::string *str, unsigned int allowed_size, Mutator m) {
        assert(allowed_size >= str->size());
        char buf[allowed_size];
        memcpy(buf, str->c_str(), str->size());
        size_t newsz = m((uint8_t *) buf, str->size(), allowed_size);

        // check error case, unless data was small enough that 0 might be a valid response (e.g., MutationDispatcher::Mutate_EraseByte)
        if (newsz == 0 && str->size() > 1) {
            return 0;
        }

        // SIZE_MAX is the signal from Mutate_ClearField
        if (newsz == SIZE_MAX) {
            newsz = 0;
        }

        str->assign(buf, newsz);
        return 1;
    }

    /** Performs random bit mutation on the DataFrame fields of the given Frame */
    virtual size_t mutate_dataframe(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *df = dynamic_cast<DataFrame *>(f);

        // copy dataframe data to larger buffer for mutation
        unsigned int allowed_size = MaxSize - strm_sz_ + df->data.size(); // add back data being mutated to allowed size

        switch (fr.field) {
            case FrameField::Data:
                if (allowed_size > 0) {
                    return mutate_vector_(&df->data, f, allowed_size, m);
                }
            default:
                std::cout << "Invalid field for DataFrame" << std::endl;
        }
        return 0;
    }

    /** Performs random bit mutation on the RstStreamFrame fields of the given Frame */
    virtual size_t mutate_rst_streamframe(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *rsf = dynamic_cast<RstStreamFrame *>(f);

        switch (fr.field) {
            case FrameField::ErrCode:
                // just one field to modify, and that's the error code, which is always 32 bits
                m(reinterpret_cast<uint8_t *>(&rsf->error_code), sizeof(rsf->error_code), sizeof(rsf->error_code));
                return 1;
            default:
                std::cout << "Invalid field for RstStreamFrame" << std::endl;
                return 0;
        }
    }

    template<class T>
    void split_vector(std::vector<T> *src, std::vector<T> *dst, size_t split_idx) {
        dst->insert(dst->end(),
                    std::make_move_iterator(src->begin() + split_idx),
                    std::make_move_iterator(src->end()));
        src->erase(src->begin() + split_idx, src->end());
    }

    /**
     * Splits the current settings frame at a random index into two settings frames.
     */
    size_t split_settings(SettingsFrame *sf, unsigned int MaxSize) {
        // can't split a settings frame with 1 or fewer settings
        // new frame adds 9 bytes for new frame header
        if (sf->settings.size() < 2 || this->strm_sz_ + HDRSZ > MaxSize) {
            return 0;
        }

        // find this frame within the stream (could pass the index to this function but for now it's not a priority)
        int frm_idx = -1;
        for (int i = 0; i < this->strm_->size(); ++i) {
            if (sf == this->strm_->at(i)) {
                frm_idx = i;
            }
        }
        assert(frm_idx != -1);

        // generate index in range [0, length]
        unsigned int split_idx = my_rand(sf->settings.size() + 1);

        auto *sf_new = new SettingsFrame();
        sf_new->flags = sf->flags;
        sf_new->reserved = sf->reserved;
        sf_new->stream_id = sf->stream_id;

        // from https://stackoverflow.com/questions/15004517/moving-elements-from-stdvector-to-another-one
        // move settings from [split_idx, end] to the new settings frame
        split_vector(&sf->settings, &sf_new->settings, split_idx);
        //sf_new->settings.insert(sf_new->settings.end(),
        //                    std::make_move_iterator(sf->settings.begin() + split_idx),
        //                    std::make_move_iterator(sf->settings.end()));
        //sf->settings.erase(sf->settings.begin() + split_idx, sf->settings.end());

        // update frame and stream sizes
        sf->len = 6 * sf->settings.size();
        sf_new->len = 6 * sf_new->settings.size();
        this->strm_->insert(this->strm_->begin() + frm_idx + 1, sf_new);
        strm_sz_ += HDRSZ;
        return 1;
    }

    /** Performs random bit mutation on the SettingsFrame fields of the given Frame */
    virtual size_t mutate_settingsframe(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *sf = dynamic_cast<SettingsFrame *>(f);

        if (sf->settings.empty()) {
            return 0;
        }

        unsigned int idx1 = my_rand(sf->settings.size());
        uint16_t *id = &sf->settings[idx1].first;
        uint32_t *value = &sf->settings[idx1].second;
        Setting tmp;

        switch (fr.field) {
            case FrameField::ID:
                m(reinterpret_cast<uint8_t *>(id), sizeof(*id), sizeof(*id));
                if (*id == 4) {
                    *id = 65535;  // can't let ID=4 ever be modified
                }
                return 1;
            case FrameField::Value:
                if (*id == 4) {
                    // must not mutate settings ID 4 because it can truncate proxy's response body
                    return 0;
                } else {
                    m(reinterpret_cast<uint8_t *>(value), sizeof(*value), sizeof(*value));
                    return 1;
                }
            case FrameField::Dup:
            case FrameField::Delete:
            case FrameField::Swap:
                return mutate_dup_del_swap(fr.field, f, idx1, &sf->settings, MaxSize,
                                           H2Mutator::setting_sz, H2Mutator::setting_cpy, &tmp);
            case FrameField::Split:
                return split_settings(sf, MaxSize);
            default:
                std::cout << "Invalid field for SettingsFrame" << std::endl;
                return 0;
        }
    }

    template<class T>
    size_t mutate_dup_del_swap(FrameField ff, Frame *f, size_t idx1, std::vector<T> *data, unsigned int MaxSize,
                               size_t (*sz_func)(T *), T (*copier)(T), T *orig) {
        T s1 = data->at(idx1), s2;
        unsigned int idx2;

        switch (ff) {
            case FrameField::Dup:
                if (strm_sz_ + sz_func(&s1) <= MaxSize) {
                    // TODO - is this okay for Frames? duplicates a pointer, but possibly fine if we re-serialize between mutations
                    data->insert(data->begin() + idx1, s1);
                    f->len += sz_func(&s1);
                    strm_sz_ += sz_func(&s1);
                    return 1;
                }
                break;
            case FrameField::Delete:
                data->erase(data->begin() + idx1);
                f->len -= sz_func(&s1);
                strm_sz_ -= sz_func(&s1);
                return 1;
            case FrameField::Swap:
                idx2 = my_rand(data->size());
                s2 = data->at(idx2);
                data->at(idx1) = s2;
                data->at(idx2) = s1;
                return 1;
            default:
                std::cout << "Field was neither Duplicate, Delete, nor Swap" << std::endl;
        }
        return 0;
    }

    /** Performs random bit mutation on the PushPromiseFrame fields of the given Frame */
    virtual size_t mutate_push_promiseframe(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *ppf = dynamic_cast<PushPromiseFrame *>(f);

        switch (fr.field) {
            case FrameField::Reserved:
                // bit flip
                ppf->reserved_pp = !ppf->reserved_pp;
                return 1;
            case FrameField::StreamID:
                // just mutate promised stream ID in place. always 32 bits
                m(reinterpret_cast<uint8_t *>(&ppf->prom_stream_id), sizeof(ppf->prom_stream_id),
                  sizeof(ppf->prom_stream_id));
                return 1;
            default:
                std::cout << "Invalid field for PushPromiseFrame" << std::endl;
                return 0;
        }
    }

    /** Performs random bit mutation on the PingFrame fields of the given Frame */
    virtual size_t mutate_pingframe(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *pf = dynamic_cast<PingFrame *>(f);

        switch (fr.field) {
            case FrameField::Data:
                // just one field to modify, and that's the opaque data, which is always 64 bits
                m(reinterpret_cast<uint8_t *>(&pf->data), sizeof(pf->data), sizeof(pf->data));
                return 1;
            default:
                std::cout << "Invalid field for PingFrame" << std::endl;
                return 0;
        }
    }

    /** Performs random bit mutation on the GoAway fields of the given Frame */
    virtual size_t mutate_goaway(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *ga = dynamic_cast<GoAway *>(f);

        // copy dataframe data to larger buffer for mutation
        unsigned int allowed_size = MaxSize - strm_sz_ + ga->debug_data.size();

        switch (fr.field) {
            case FrameField::Reserved:
                // bit flip
                ga->reserved_ga = !ga->reserved_ga;
                return 1;
            case FrameField::StreamID:
                // mutate last stream ID in place. always 32 bits
                m(reinterpret_cast<uint8_t *>(&ga->last_stream_id), sizeof(ga->last_stream_id),
                  sizeof(ga->last_stream_id));
                return 1;
            case FrameField::ErrCode:
                // mutate error code in place. always 32 bits
                m(reinterpret_cast<uint8_t *>(&ga->error_code), sizeof(ga->error_code), sizeof(ga->error_code));
                return 1;
            case FrameField::Data:
                if (allowed_size > 0) {
                    return mutate_vector_(&ga->debug_data, f, allowed_size, m);
                }
            default:
                std::cout << "Invalid field for GoAway" << std::endl;
        }
        return 0;
    }

    /** Performs random bit mutation on the WindowUpdate fields of the given Frame */
    virtual size_t mutate_window_updateframe(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *wu = dynamic_cast<WindowUpdate *>(f);

        switch (fr.field) {
            case FrameField::Reserved:
                // bit flip
                wu->reserved_wu = !wu->reserved_wu;
                return 1;
            case FrameField::Increment:
                // mutate increment in place. always 32 bits
                m(reinterpret_cast<uint8_t *>(&wu->win_sz_inc), sizeof(wu->win_sz_inc), sizeof(wu->win_sz_inc));
                return 1;
            default:
                std::cout << "Invalid field for WindowUpdate" << std::endl;
                return 0;
        }
    }

    /** Performs random bit mutation on the BaseFrame fields of the given Frame */
    virtual size_t mutate_baseframe(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        uint8_t pad_orig;
        uint8_t priority_orig;
        switch (fr.field) {
            case FrameField::Length:
                m(reinterpret_cast<uint8_t *>(&f->len), sizeof(f->len), sizeof(f->len));
                return 1;
            case FrameField::Type:
                m(reinterpret_cast<uint8_t *>(&f->type), sizeof(f->type), sizeof(f->type));
                return 1;
            case FrameField::Flags:
                // store original padded and priority flag values so that we can reset them
                // must do this because setting/unsetting them affects size of frame
                pad_orig = f->flags & FLAG_PADDED;
                priority_orig = f->flags & FLAG_PRIORITY;

                m(reinterpret_cast<uint8_t *>(&f->flags), sizeof(f->flags), sizeof(f->flags));

                // unset flags then add back original values
                f->flags &= ~FLAG_PADDED;
                f->flags &= ~FLAG_PRIORITY;
                f->flags += pad_orig;
                f->flags += priority_orig;
                return 1;
            case FrameField::Reserved:
                f->reserved = !f->reserved; // bit flip
                return 1;
            case FrameField::StreamID:
                m(reinterpret_cast<uint8_t *>(&f->stream_id), sizeof(f->stream_id), sizeof(f->stream_id));
                return 1;
            default:
                std::cout << "Invalid field for BaseFrame" << std::endl;
                return 0;
        }
    }

    /** Performs random bit mutation on the DepWeight fields of the given Frame */
    virtual size_t mutate_depweight(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *dw = dynamic_cast<DepWeight *>(f);

        switch (fr.field) {
            case FrameField::Exclusive:
                dw->exclusive = !dw->exclusive; // bit flip
                return 1;
            case FrameField::StreamID:
                m(reinterpret_cast<uint8_t *>(&dw->stream_dep), sizeof(dw->stream_dep), sizeof(dw->stream_dep));
                return 1;
            case FrameField::Weight:
                m(reinterpret_cast<uint8_t *>(&dw->weight), sizeof(dw->weight), sizeof(dw->weight));
                return 1;
            default:
                std::cout << "Invalid field for DepWeight" << std::endl;
                return 0;
        }
    }

    /**
     * Returns a random HPacker PrefixType.
     *
     * full_idx_ok controls whether INDEXED_HEADER can be returned by this function
     */
    PrefType rand_pref(bool full_idx_ok) {
        int limit = full_idx_ok ? 4 : 3;  // allow INDEXED_HEADER only if name and value are in the table
        switch (my_rand(limit)) {
            case 0:
                return PrefType::LITERAL_HEADER_WITH_INDEXING;
            case 1:
                return PrefType::LITERAL_HEADER_NEVER_INDEXED;
            case 2:
                return PrefType::LITERAL_HEADER_WITHOUT_INDEXING;
            default:
                return PrefType::INDEXED_HEADER;
        }
    }

    /** Returns a random HPacker IndexingType */
    IdxType rand_idx_type() {
        // NOTE: index type set to ALL manually if prefix is INDEXED_HEADER, so we never return ALL here
        if (!my_rand(2)) {
            return IdxType::NONE;
        } else {
            return IdxType::NAME;
        }
    }

    /**
     * Populates the given sets with all headers that are inserted into the dynamic table prior to the header at the
     * given index within the given Frame.
     *
     * nv_pairs is filled with HPacker::KeyValuePairs -- that is, the name and value together
     * names is filled with just the names
     */
    void headers_in_table(std::set<HPacker::KeyValuePair> &nv_pairs, std::set<std::string> &names, Frame *f,
                          unsigned int idx) const {
        // clear tables just in case
        nv_pairs.clear();
        names.clear();

        // start with static table
        for (auto &nv: hpack::hpackStaticTable) {
            nv_pairs.insert(nv);
            names.insert(nv.first);
        }

        // loop over all frames looking for any with headers
        for (auto f_iter: *(this->strm_)) {
            if (!Frame::has_headers(f_iter)) {
                // must check if this is terminating frame
                if (f_iter == f) {
                    return;
                }
                continue;
            }
            auto *h = dynamic_cast<Headers *>(f_iter);  // the prior check ensures this will not return nullptr

            // if this loop's frame is not the target frame, check all headers
            // otherwise, check only up to the header just before the target header
            unsigned int max_hdr_idx = (f_iter != f) ? h->hdr_pairs.size() : idx;
            for (unsigned int i = 0; i < max_hdr_idx; ++i) {
                if (h->prefixes[i] == PrefType::LITERAL_HEADER_WITH_INDEXING) {
                    nv_pairs.insert(h->hdr_pairs[i]);
                    names.insert(h->hdr_pairs[i].first);
                }
            }

            // if this is target frame, return since no more to check
            if (f_iter == f) {
                return;
            }
        }
    }

    /**
     * Following a mutation of a header that had been inserted into the dynamic table, loop through all subsequent
     * headers and update their prefixes and indexing types such that the table remains valid. The assumption here is
     * that no future headers can use any part of this header, because either its encoding or name changed.
     *
     * When this algorithm finds an exact match of the given header, it ensures that it is added to the table and then
     * returns.
     *
     * If it encounters a name-only match before it finds an exact match (and the name was not available somewhere in
     * the table), then it adds THAT header to the table and keeps scanning for an exact match.
     *
     * @param f the exact frame in which the header resides
     * @param idx the index of "hdr" within "f"
     * @param hdr a copy of the <name, value> pair before it was mutated
     * @param name_idx_ok whether or not the header's name is present in the hpack table
     * @param one_frame whether to terminate after updating just one frame
     * @param end_idx when specified, the final header in the given frame to check for dependencies
     */
    void post_patch_header_encodings(Frame *f, long idx, const HPacker::KeyValuePair &hdr, bool name_idx_ok,
                                     bool one_frame = false, long end_idx = -1, long end_f_idx = -1) {
        bool found_name_only = false;

        // find index of f within the stream
        unsigned int start_f_idx = 0;
        for (auto f_iter: *(this->strm_)) {
            if (f_iter == f) { break; }
            ++start_f_idx;
        }

        end_f_idx = (end_f_idx == -1) ? (int) this->strm_->size() - 1 : end_f_idx;
        for (unsigned int j = start_f_idx; j <= end_f_idx; ++j) {
            Frame *f_iter = this->strm_->at(j);

            // only care about frames with headers
            if (!Frame::has_headers(f_iter)) {
                continue;
            }
            auto hf_iter = dynamic_cast<Headers *>(f_iter);

            // loop over all headers starting after this one, up to, possible end_idx, if specified
            unsigned int start_idx;
            if (f_iter == f) {
                start_idx = idx + 1;
                end_idx = (end_idx == -1) ? (int) hf_iter->hdr_pairs.size() - 1 : end_idx;
            } else {
                start_idx = 0;
                end_idx = (int) hf_iter->hdr_pairs.size() - 1;
            }
            for (unsigned int i = start_idx; i <= end_idx; ++i) {
                // scan for a true match of this header and add it to table.
                // resolves all future dependencies and so we can return immediately
                if (hf_iter->hdr_pairs[i] == hdr) {
                    hf_iter->prefixes[i] = PrefType::LITERAL_HEADER_WITH_INDEXING; // add to table

                    // if we previously found a name match, we add it to table, so we can NAME index
                    unsigned int orig_sz = hdr_sz(&hf_iter->hdr_pairs[i], hf_iter->idx_types[i]);
                    hf_iter->idx_types[i] = found_name_only ? IdxType::NAME : IdxType::NONE;
                    unsigned int new_sz = hdr_sz(&hf_iter->hdr_pairs[i], hf_iter->idx_types[i]);

                    // implicitly, the way we computed orig_sz and new_sz handles the case where we made no change to
                    // the header because the first occurrence already matched the desired encoding. new_sz-orig_sz = 0
                    f_iter->len = f_iter->len + new_sz - orig_sz;
                    strm_sz_ = strm_sz_ + new_sz - orig_sz;
                    return;
                }
                    // if name was not already in table, future headers may do name indexing based on this header's
                    // position into the table, so we must add these to table as well
                else if (!name_idx_ok && !found_name_only && hf_iter->hdr_pairs[i].first == hdr.first) {
                    found_name_only = true;
                    unsigned int orig_sz = hdr_sz(&hf_iter->hdr_pairs[i], hf_iter->idx_types[i]);
                    hf_iter->prefixes[i] = PrefType::LITERAL_HEADER_WITH_INDEXING; // add to table
                    hf_iter->idx_types[i] = IdxType::NONE; // no indexing since it's not in the table yet
                    unsigned int new_sz = hdr_sz(&hf_iter->hdr_pairs[i], hf_iter->idx_types[i]);
                    f_iter->len = f_iter->len + new_sz - orig_sz;
                    strm_sz_ = strm_sz_ + new_sz - orig_sz;
                }
            }

            // after we have made a pass through all headers in this frame, check if we should check rest of stream
            if (one_frame) {
                return;
            }
        }
    }

    /** Helper function that returns whether the given "val" exists within the given set "s" */
    template<class T>
    bool set_contains(std::set<T> s, T val) {
        return s.find(val) != s.end();
    }

    /**
     * Performs a mutation on the HPACK encoding of the header at the given index in f
     * @param f the frame in which the target header resides
     * @param idx the index of the target header
     * @param MaxSize the maximum size that the HTTP/2 stream may occupy when serialized
     * @param nv_pairs set of all <name, value> pairs in the hpack table prior to this header
     * @param names set of all http header names in the hpack table prior to this header
     */
    size_t mutate_encoding(Frame *f, unsigned int idx, unsigned int MaxSize,
                           std::set<HPacker::KeyValuePair> &nv_pairs, std::set<std::string> &names) {
        auto hf = dynamic_cast<Headers *>(f);
        HPacker::KeyValuePair hdr = hf->hdr_pairs[idx];

        /*
         * Updating the encoding of this header may update the size of this header AND multiple headers after it. This
         * comment demonstrates that we can always guarantee a maximum increase of the size of a fully-literally-encoded
         * header minus 1 byte.
         *
         * At the time of performing the mutation, there are three possible scenarios about the availability of this
         * header in either the dynamic or static table:
         *
         * Case 1: header name and value are already in the static or dynamic table:
         *   - min cur size = 1 byte (fully indexed)
         *   - max new size = 1 + name_length + name_string + val_length + val_string
         *   - no need to check dependencies, since this header is already in the table
         *   - max diff = name_length + name_string + val_length + val_string
         *
         * Case 2: header name in static/dynamic table, but not the value
         *   - min cur size = 1 + val_length + val_string (name indexed)
         *   - max new size = 1 + name_length + name_string + val_length + val_string
         *   - worst case, header was inserted into table, now isn't, and future headers are fully indexed
         *   - scan through table and make next occurrence a literal inserted into table
         *   - this header can be name indexed, so size goes from 1 to 1 + val_length + val_string
         *   - thus, max diff = name_length + name_string + val_length + val_string
         *   - ^^ assuming we set first occurrence to name indexed
         *
         * Case 3: neither name nor value in static/dynamic table
         *   - min cur size = 1 + name_length + name_string + val_length + val_string
         *   - can't increase size beyond this, so no diff on header itself
         *   - worst case, header is inserted into table, and future headers are name AND full indexed
         *   - Case 3.1: first encounter a name-only match (indexed name), then a fully indexed copy
         *      - make first header a literal header and insert into table
         *          - diff = name_length + name_string (since its value is already a literal)
         *      - make second header a literal, but name indexed, and insert into table
         *          - diff = value_length + value_string (we can index name since we inserted into table in the first match)
         *      - total diff = name_length + name_string + value_length + value_string
         *   - Case 3.2: after header, encounter a fully indexed copy
         *      - make this a literal and insert into the table
         *          - diff = name_length + name_string + value_length + value_string
         *   - thus, max diff = name_length + name_string + value_length + value_string
         */
        size_t sz = hdr_sz(&hdr) - 1;  // maximum possible size increase by applying given mutation
        bool full_idx_ok = set_contains(nv_pairs, hdr);
        bool name_idx_ok = set_contains(names, hdr.first);

        // exit if we can't make mutation
        if (strm_sz_ + sz > MaxSize) {
            return 0;
        }
        PrefType prev_pref = hf->prefixes[idx]; // back up prev prefix for future logic

        DEBUG("mutating encoding of " << hdr.first << ":" << hdr.second)
        DEBUG("orig pref/idx = " << (int) hf->prefixes[idx] << "/" << (int) hf->idx_types[idx])

        // pick random (allowed) prefix and indexing type
        unsigned int orig_sz = hdr_sz(&hdr, hf->idx_types[idx]);
        hf->prefixes[idx] = rand_pref(full_idx_ok);
        if (hf->prefixes[idx] == PrefType::INDEXED_HEADER) {
            hf->idx_types[idx] = IdxType::ALL;  // indexed header is always ALL
        } else if (name_idx_ok) {
            hf->idx_types[idx] = rand_idx_type(); // only pick random if we *can* name index the header
        } else {
            hf->idx_types[idx] = IdxType::NONE;
        }

        // update sizes
        unsigned int new_sz = hdr_sz(&hdr, hf->idx_types[idx]);
        f->len = f->len + new_sz - orig_sz;
        strm_sz_ = strm_sz_ + new_sz - orig_sz;

        DEBUG("new pref/idx = " << (int) hf->prefixes[idx] << "/" << (int) hf->idx_types[idx])

        // if this header was not originally in the table and was being inserted here, but now, due to mutation, is not
        // and could not have originally been fully indexed...
        if (!full_idx_ok &&
            prev_pref == PrefType::LITERAL_HEADER_WITH_INDEXING &&
            hf->prefixes[idx] != PrefType::LITERAL_HEADER_WITH_INDEXING) {
            post_patch_header_encodings(f, idx, hdr, name_idx_ok);
        }
        return 1;
    }

    /**
     * Performs a mutation on the name value of the header at the given index in f
     * @param f the frame in which the target header resides
     * @param idx the index of the target header
     * @param MaxSize the maximum size that the HTTP/2 stream may occupy when serialized
     * @param m the Mutator function that performs the base mutation operations on the name
     * @param nv_pairs set of all <name, value> pairs in the hpack table prior to this header
     * @param names set of all http header names in the hpack table prior to this header
     */
    size_t mutate_name(Frame *f, unsigned int idx, unsigned int MaxSize, Mutator m,
                       std::set<HPacker::KeyValuePair> &nv_pairs, std::set<std::string> &names) {
        auto hf = dynamic_cast<Headers *>(f);
        HPacker::KeyValuePair hdr = hf->hdr_pairs[idx];
        unsigned int value_size = hpack_int_length(hdr.second.size()) + hdr.second.size();
        PrefType pref = hf->prefixes[idx];
        IdxType idxType = hf->idx_types[idx];

        bool full_idx_ok = set_contains(nv_pairs, hdr);
        bool name_idx_ok = set_contains(names, hdr.first);

        unsigned int allowed_size;

        /* if fully indexed, mutation may increase size by name + value
         * strm_sz currently includes 1 byte for this header
         * must subtract value_size since mutating the name will result in the value being expanded in the buffer
         * | 1 |                            |
         * | 1 | NL | NEW_NAME | VALUE |    |
         * 0                                MaxSize
         *
         * if name indexed AND inserted into table, mutation my increase size by name + value
         * strm_sz_ currently includes 1 byte for the name and a value literal
         * must subtract value_size since a future fully-indexed header may have to be expanded to have a literal value
         * | 1 | VALUE || 1 |                           |
         * | 1 | NL | NEW_NAME | VALUE || 1 | VALUE |   |
         * 0                                            MaxSize
         *
         * if no indexing at all and header IS inserted into table, mutation may increase size by name + value
         * strm_sz_ currently includes 1 byte + name and value literals, and may include a new name and value literal
         * being added, so we must subtract a hdr_sz - 1 from allowed_size. BUT name is already a literal. allowed_size
         * is the maximum size the mutator function can RETURN. this means that it must be at least as big as the buffer
         * it is mutating, so it can mutate in-place thus, add BACK the name size since we can return at least that much
         * data. because we add the name size after subtracting it, we really only have to subtract the value length
         * | 1 | NAME | VALUE || 1 | VALUE_2 || 1 |                     |
         * | 1 | NL | NEW_NAME | VALUE || 1 | NAME | VALUE_2 || 1 | VALUE|   |
         * 0                                                            MaxSize
         *
         * | 1 | NAME | VALUE || 1 |                            |
         * | 1 | NL | NEW_NAME | VALUE || 1 | NAME | VALUE |    |
         * 0                                                    MaxSize
         */
        if (
                (idxType == IdxType::ALL) ||
                (idxType == IdxType::NAME && pref == PrefType::LITERAL_HEADER_WITH_INDEXING) ||
                (idxType == IdxType::NONE && pref == PrefType::LITERAL_HEADER_WITH_INDEXING)) {
            if (strm_sz_ + hdr_sz(&hdr) - 1 > MaxSize) return 0;
            allowed_size = MaxSize - strm_sz_ - value_size - hpack_int_length(hdr.first.size());
        }
            /* if name indexed and NOT inserted into table, mutation may increase size by name.
             * name goes from 1 indexed byte to 1 byte prefix + literal header, so allowed size is just whatever space is
             * not occupied by the stream
             * | 1 | VALUE |                            |
             * | 1 | NL | NEW_NAME | VALUE |      |
             * 0                                        MaxSize
             */
        else if (idxType == IdxType::NAME) {
            if (strm_sz_ + hpack_int_length(hdr.first.size()) + hdr.first.size() > MaxSize) return 0;
            allowed_size = MaxSize - strm_sz_ - hpack_int_length(hdr.first.size());
        }
            /* if no indexing at all and header is NOT inserted into table, there are no bounds to check at all, as header
             * can at least be mutated in place with no worry
             * since the name itself is already a literal, we add back its own length to allowed_size
             * | 1 | NL | NAME | VALUE |            |
             * | 1 | NL | NEW_NAME | VALUE |        |
             * 0                                    MaxSize
             */
        else if (idxType == IdxType::NONE) {
            allowed_size = MaxSize - strm_sz_ + hdr.first.size();
        } else {
            throw std::runtime_error("Invalid index type and prefix combination reached in mutate_name");
        }

        // control header size so that we don't have to account for integer encoding changes
        if (allowed_size >= 127) {
            allowed_size = 126;
        }
        unsigned int orig_sz = hdr_sz(&hf->hdr_pairs[idx], hf->idx_types[idx]);

        // finally perform mutation
        if (!mutate_string_(&hf->hdr_pairs[idx].first, allowed_size, m)) {
            return 0;
        }

        // update prefix and indexing types of header we just mutated
        if (pref == PrefType::INDEXED_HEADER && !set_contains(nv_pairs, hf->hdr_pairs[idx])) {
            // add to table to improve compression and optimistically set to name indexed
            // next "if" statement will check if name indexing is valid
            hf->prefixes[idx] = PrefType::LITERAL_HEADER_WITH_INDEXING;
            hf->idx_types[idx] = IdxType::NAME;
        }
        if (hf->idx_types[idx] != IdxType::NONE && !set_contains(names, hf->hdr_pairs[idx].first)) {
            hf->idx_types[idx] = IdxType::NONE;
        }
        unsigned int new_sz = hdr_sz(&hf->hdr_pairs[idx], hf->idx_types[idx]);
        f->len = f->len + new_sz - orig_sz;
        strm_sz_ = strm_sz_ + new_sz - orig_sz;

        // if this header was not already in the table and was previously inserted into it, update future header
        // encodings to ensure that the hpack table stays valid
        if (!full_idx_ok && pref == PrefType::LITERAL_HEADER_WITH_INDEXING) {
            post_patch_header_encodings(f, idx, hdr, name_idx_ok);
        }
        return 1;
    }

    /**
     * After mutating the value of a header, iterate through all subsequent headers and set the first header that matches
     * the one at the given index (idx) in "f" to be inserted into the dynamic table
     */
    void post_patch_header_encodings_value(Frame *f, HPacker::KeyValuePair &hdr, unsigned int idx) {
        bool found_curframe = false;
        auto hf = dynamic_cast<Headers *>(f);
        assert(hf != nullptr);

        for (auto f_iter: *(this->strm_)) {
            // ignore frames until we find current frame
            if (!found_curframe) {
                if (f_iter == f) { found_curframe = true; }
                else { continue; }
            }

            // only care about frames with headers
            if (!Frame::has_headers(f_iter)) {
                continue;
            }
            auto hf_iter = dynamic_cast<Headers *>(f_iter);

            // loop over all headers starting after this one
            unsigned int start_idx = (f_iter == f) ? idx + 1 : 0;
            for (unsigned int i = start_idx; i < hf_iter->hdr_pairs.size(); ++i) {
                // scan for a true match of this header and add it to table. resolves all future dependencies
                // and so we can return immediately
                if (hf_iter->hdr_pairs[i] == hdr) {
                    hf_iter->prefixes[i] = PrefType::LITERAL_HEADER_WITH_INDEXING; // add to table

                    unsigned int orig_sz = hdr_sz(&hdr, hf_iter->idx_types[i]);
                    hf_iter->idx_types[i] = IdxType::NAME;  // we can name index since this mutated was added to table
                    unsigned int new_sz = hdr_sz(&hdr, hf_iter->idx_types[i]);

                    f_iter->len = f_iter->len + new_sz - orig_sz;
                    strm_sz_ = strm_sz_ + new_sz - orig_sz;
                    return;
                }
            }
        }
    }

    bool do_value_mutation(Headers *hf, HPacker::KeyValuePair &hdr, unsigned int idx, unsigned int allowed_size, Mutator m) {
        unsigned int smart_val_cutoff = 50;
        unsigned int rval = my_rand(100);
        std::string name_lower;
        for (char c: hdr.first) {
            name_lower += (char) std::tolower(c);
        }

        size_t avail_space = allowed_size - hdr.second.size();  // space we can grow beyond current value bounds

        if (rval < smart_val_cutoff) {
            std::string smart_val;

            // allowed_size must be >= length of longest possible smart value + 1 (in case of comma)
            if (name_lower == ":method" && allowed_size >= 8) {
                std::vector<std::string> methods{"DELETE", "GET", "HEAD", "POST", "PUT", "CONNECT", "OPTIONS", "TRACE"};
                smart_val = methods[my_rand(methods.size())];
            } else if (name_lower == ":status" && allowed_size >= 4) {
                unsigned int code = 100 + my_rand(500); // 100 -> 599
                smart_val = std::to_string(code);
            } else if (name_lower == ":scheme" && allowed_size >= 6) {
                std::vector<std::string> schemes{"http", "https"};
                smart_val = schemes[my_rand(schemes.size())];
            } else if ((Util::special_match(name_lower, "transfer-encoding") || Util::special_match(name_lower, "te"))
                       && allowed_size >= 9) {
                std::vector<std::string> encodings{"chunked", "identity", "gzip", "trailers"};
                smart_val = encodings[my_rand(encodings.size())];
            } else if (name_lower == "connection" && allowed_size >= 11) {
                std::vector<std::string> tokens{"close", "host", "cookie", "keep-alive", "upgrade"};
                smart_val = tokens[my_rand(tokens.size())];
            } else if (Util::special_match(name_lower, "content-length") && allowed_size >= 7) {
                // smart CL values are: 1) random int between 0 and 999999
                //                      2) the current content-length value
                //                      3) the actual amount of data in all dataframes of this stream
                //                      4) the actual amount of data in all dataframes BEFORE the ES flag
                // ^ each of the above expressed as decimal or as hex (where possible)
                unsigned int randint = my_rand(1000000);
                std::vector<std::string> smart_cls{std::to_string(randint), Util::to_hex(randint),
                                                   hf->hdr_pairs[idx].second};

                // add current CL value as hex (if it can be converted. don't try to parse csv)
                try {
                    unsigned int curval = std::stoi(hf->hdr_pairs[idx].second);
                    smart_cls.push_back(Util::to_hex(curval));
                } catch (const std::invalid_argument &e) {}

                // compute total data in dataframes in general and only up to ES flag
                // add both values to smart_cls as decimal and hex
                unsigned int tot_data = 0;
                for (auto f: *this->strm_) {
                    if (f->type == DATA) {
                        auto df = dynamic_cast<DataFrame *>(f);
                        if (df == nullptr) {
                            return false;
                        }

                        tot_data += df->data.size();
                        if (f->flags & FLAG_END_STREAM) {
                            smart_cls.push_back(std::to_string(tot_data));
                            smart_cls.push_back(Util::to_hex(tot_data));
                        }
                    }
                }
                smart_cls.push_back(std::to_string(tot_data));
                smart_cls.push_back(Util::to_hex(tot_data));

                smart_val = smart_cls[my_rand(smart_cls.size())];
            }
            /******
             *  the next headers do NOT have comma-separated values
             ******/
            else if (name_lower == "expect" && allowed_size >= 12) {
                hf->hdr_pairs[idx].second = "100-continue";
                return true;
            } else if ((name_lower == ":authority" || Util::special_match(name_lower, "host") || name_lower == ":path")
                       && allowed_size >= strlen(GRAMMAR_AUTH) + 1) {
                // prepend to the authority/host or path to see if we can forward differing values
                std::vector<std::string> vals{GRAMMAR_AUTH, "https://", "http://", "test://", "test.com@"};
                smart_val = vals[my_rand(vals.size())];
                if ((rval < smart_val_cutoff / 2) && (1 + smart_val.size() <= avail_space)) {
                    hf->hdr_pairs[idx].second = smart_val + hf->hdr_pairs[idx].second;
                    return true;
                }
            }

            // either assign smart value or append as comma-separated list
            if (!smart_val.empty()) {
                if (rval < smart_val_cutoff / 2) {
                    // check whether we would be growing PAST the allowed space
                    if (1 + smart_val.size() <= avail_space) {
                        hf->hdr_pairs[idx].second += "," + smart_val;
                        return true;
                    }
                } else {
                    hf->hdr_pairs[idx].second = smart_val;
                    return true;
                }
            }
        }

        // default to random mutation
        if (!mutate_string_(&hf->hdr_pairs[idx].second, allowed_size, m)) {
            return false;
        }
        return true;
    }

    /**
     * Performs a mutation on the "value" part of the header at the given index in f
     * @param f the frame in which the target header resides
     * @param idx the index of the target header
     * @param MaxSize the maximum size that the HTTP/2 stream may occupy when serialized
     * @param m the Mutator function that performs the base mutation operations on the name
     * @param nv_pairs set of all <name, value> pairs in the hpack table prior to this header
     * @param names set of all http header names in the hpack table prior to this header
     */
    size_t mutate_value(Frame *f, unsigned int idx, unsigned int MaxSize, Mutator m,
                        std::set<HPacker::KeyValuePair> &nv_pairs) {
        /**
         * Case 1: header name and value are already in the static or dynamic table:
         * | 1 |                 |         <- originally fully indexed
         * | 1 | NEW_VALUE |     |         <- because name already in table, keep name indexed and make value literal
         * 0                     MaxSize
         *   - if strm_sz_ + val_int + val > MaxSize, abort
         *   - allowed_size = MaxSize - strm_sz_ - val_int
         *
         * Case 2: header name in static/dynamic table, but not the value
         * | 1 | VALUE || 1 |                |        <- hdr name indexed and inserted, copy fully indexed
         * | 1 | NEW_VALUE || 1 | VALUE |    |        <- hdr stays name indexed, but copy becomes name indexed
         * 0                                 MaxSize
         *   - if strm_sz_ + val_int + val > MaxSize, abort
         *   - allowed_size = MaxSize - strm_sz_ - val_int
         *
         * Case 3: neither name nor value in static/dynamic table
         *   - Case 3.1: first encounter a name-only match (indexed name), then a fully indexed copy
         * | 1 | NAME | VALUE || 1 | VALUE_2 || 1 |                 |
         * | 1 | NAME | NEW_VALUE || 1 | VALUE_2 || 1 | VALUE |     |
         * 0                                                        MaxSize
         *
         *   - Case 3.2: after header, encounter a fully indexed copy
         * | 1 | NAME | VALUE || 1 |                 |
         * | 1 | NAME | NEW_VALUE || 1 | VALUE |     |
         * 0                                         MaxSize
         *   - unlike in encoding and name mutations, the name-only match is unchanged
         *   - if strm_sz_ + val_int + val > MaxSize, abort
         *   - allowed_size = MaxSize - strm_sz_ - val_int
         */
        auto hf = dynamic_cast<Headers *>(f);
        HPacker::KeyValuePair hdr = hf->hdr_pairs[idx];
        unsigned int value_size = hpack_int_length(hdr.second.size()) + hdr.second.size();
        PrefType pref = hf->prefixes[idx];
        IdxType idxType = hf->idx_types[idx];
        bool full_idx_ok = set_contains(nv_pairs, hdr);

        // if this header is fully indexed or is inserted into the table, the hpack block will expand due to changes in
        // encodings. ensure here that in the worst case, this will not exceed MaxSize
        if ((idxType == IdxType::ALL || pref == PrefType::LITERAL_HEADER_WITH_INDEXING) &&
            (strm_sz_ + value_size > MaxSize)) {
            return 0;
        }

        // control header size so that we don't have to account for integer encoding changes
        unsigned int allowed_size = MaxSize - strm_sz_ + hdr.second.size();
        if (allowed_size >= 127) {
            allowed_size = 126;
        }
        unsigned int orig_sz = hdr_sz(&hf->hdr_pairs[idx], hf->idx_types[idx]);

        // perform actual mutation
        if (!do_value_mutation(hf, hdr, idx, allowed_size, m)) {
            return 0;
        }

        // update prefix and indexing types of header we just mutated
        // only matters if it's fully indexed, since anything else is unchanged by value mutations
        if (pref == PrefType::INDEXED_HEADER && !set_contains(nv_pairs, hf->hdr_pairs[idx])) {
            // add to table to improve compression
            // can safely name index since name guaranteed to be in table still
            hf->prefixes[idx] = PrefType::LITERAL_HEADER_WITH_INDEXING;
            hf->idx_types[idx] = IdxType::NAME;
        }
        unsigned int new_sz = hdr_sz(&hf->hdr_pairs[idx], hf->idx_types[idx]);
        f->len = f->len + new_sz - orig_sz;
        strm_sz_ = strm_sz_ + new_sz - orig_sz;

        // if this header was not already in the table and was previously inserted into it, update future header
        // encodings to ensure that the hpack table stays valid
        if (!full_idx_ok && pref == PrefType::LITERAL_HEADER_WITH_INDEXING) {
            post_patch_header_encodings_value(f, hdr, idx);
        }
        return 1;
    }

    /**
     * Deletes the header at the given index in f from the stream, updating the header encodings of any future headers
     * that depend on it
     */
    size_t delete_header(Frame *f, unsigned int idx,
                         std::set<HPacker::KeyValuePair> &nv_pairs, std::set<std::string> &names) {
        /*
         * header deletion can always take place
         *
         * if header is fully indexed, there can be no dependencies, so size decreases by 1 byte
         * | 1 | -> ||
         *
         * if header is name indexed and a future header is fully indexed based on it, size decreases by 1 byte at least
         * must update future header to have literal value and inserted into table
         * | 1 | VALUE || 1 |
         * | 1 | VALUE ||
         *
         * if header has no indexing and neither name nor value are available:
         * size decreases by 1 worst case no matter order of headers encountered next
         * | 1 | NAME | VALUE || 1 |
         * | 1 | NAME | VALUE |
         *
         * | 1 | NAME | VALUE || 1 | VALUE_2 || 1 |
         * | 1 | NAME | VALUE_2 || 1 | VALUE ||
         */
        auto hf = dynamic_cast<Headers *>(f);

        // backups before deletion
        HPacker::KeyValuePair hdr = hf->hdr_pairs[idx];
        PrefType pref = hf->prefixes[idx];
        IdxType idxType = hf->idx_types[idx];
        bool full_idx_ok = set_contains(nv_pairs, hdr);
        bool name_idx_ok = set_contains(names, hdr.first);

        if (!full_idx_ok && pref == PrefType::LITERAL_HEADER_WITH_INDEXING) {
            post_patch_header_encodings(f, idx, hdr, name_idx_ok);
        }

        // perform deletion
        // done AFTER post-patch since post_patch_header_encodings assumes original header still located at "idx"
        hf->hdr_pairs.erase(hf->hdr_pairs.begin() + idx);
        hf->prefixes.erase(hf->prefixes.begin() + idx);
        hf->idx_types.erase(hf->idx_types.begin() + idx);

        // post processing
        unsigned int sz = hdr_sz(&hdr);
        if (pref == PrefType::INDEXED_HEADER) {
            sz = 1;
        } else if (idxType == IdxType::NAME) {
            sz -= hpack_int_length(hdr.first.size()) + hdr.first.size();
        }

        f->len -= sz; // the actual f->len is recomputed at time of serialization, so it's fine to overestimate
        strm_sz_ -= sz;
        return 1;
    }

    /**
     * Swaps the header at the given index in f with another header at a random index, as long as the swap does not
     * increase the size of the stream past MaxSize
     */
    size_t swap_headers(Frame *f, unsigned int idx, unsigned int MaxSize) {
        auto hf = dynamic_cast<Headers *>(f);
        unsigned int idx2 = my_rand(hf->hdr_pairs.size());
        if (idx == idx2) {
            return 0;
        }

        unsigned int idx_sm = std::min(idx, idx2);
        unsigned int idx_lg = std::max(idx, idx2);
        HPacker::KeyValuePair hdr_sm = hf->hdr_pairs[idx_sm];
        HPacker::KeyValuePair hdr_lg = hf->hdr_pairs[idx_lg];

        std::set<HPacker::KeyValuePair> nv_pairs;
        std::set<std::string> names;
        headers_in_table(nv_pairs, names, f, idx_sm); // only check up to smaller index

        /*
         * conditions that must be satisfied to freely perform swap without bounds or dependency checks:
         *   1) hdr_sm is present in nv_pairs OR is not inserted into the table
         *   2) hdr_lg is not indexed OR is present in nv_pairs OR is name indexed and the name is in names
         */
        bool hdr_sm_ok = set_contains(nv_pairs, hdr_sm) ||
                         hf->prefixes[idx_sm] != PrefType::LITERAL_HEADER_WITH_INDEXING;
        bool hdr_lg_ok = hf->idx_types[idx_lg] == IdxType::NONE ||
                         set_contains(nv_pairs, hdr_lg) ||
                         (hf->idx_types[idx_lg] == IdxType::NAME && set_contains(names, hdr_lg.first));

        unsigned int sz_update = 0;
        if (!hdr_sm_ok) {
            // worst case is that hdr_sm results in a full header size increase (as if you change encoding)
            // size of hdr_sm itself cannot change because if it was indexed at all, it still will be at a larger index
            sz_update += hdr_sz(&hdr_sm) - 1;
        }
        if (!hdr_lg_ok) {
            // worst case is that hdr_lg was encoded in a way that depended on a header between index sm and lg-1
            // full index -> full literal
            sz_update += hdr_sz(&hdr_lg) - 1;
        }

        // terminate early if worst case size update exceeds bounds
        if (strm_sz_ + sz_update > MaxSize) {
            return 0;
        }

        // if header at larger index needs post-processing, update its encoding to be valid
        if (!hdr_lg_ok) {
            hf->prefixes[idx_lg] = PrefType::LITERAL_HEADER_WITH_INDEXING; // add to table for later deps
            hf->idx_types[idx_lg] = set_contains(names, hdr_lg.first) ? IdxType::NAME : IdxType::NONE;
        }

        // if header at smaller index needs post-processing, update future headers' encodings
        if (!hdr_sm_ok) {
            post_patch_header_encodings(f, idx_sm, hdr_sm, set_contains(names, hdr_sm.first),
                                        true, idx_lg - 1);
        }

        // perform swap
        std::iter_swap(hf->hdr_pairs.begin() + idx, hf->hdr_pairs.begin() + idx2);
        std::iter_swap(hf->prefixes.begin() + idx, hf->prefixes.begin() + idx2);
        std::iter_swap(hf->idx_types.begin() + idx, hf->idx_types.begin() + idx2);
        return 1;
    }

    /**
     * Splits the current headers block at a random index into two frames.
     * The first frame takes the same type as the given frame, while the second
     * is a Continuation frame.
     */
    size_t split_headers(Frame *f, unsigned int MaxSize) {
        auto hf = dynamic_cast<Headers *>(f);
        if (hf->hdr_pairs.size() < 2 || this->strm_sz_ + HDRSZ > MaxSize) {
            return 0;
        }

        int frm_idx = -1;
        for (int i = 0; i < this->strm_->size(); ++i) {
            if (f == this->strm_->at(i)) {
                frm_idx = i;
            }
        }
        assert(frm_idx != -1);

        unsigned int split_idx = my_rand(hf->hdr_pairs.size() + 1);

        // unlike splitting settings, we don't copy over all flags -- just EH
        auto *new_cont = new Continuation();
        new_cont->stream_id = f->stream_id;
        if (f->flags & FLAG_END_HEADERS) {
            f->flags &= ~FLAG_END_HEADERS;
            new_cont->flags |= FLAG_END_HEADERS;
        }

        // split all three headers vectors
        split_vector(&hf->hdr_pairs, &new_cont->hdr_pairs, split_idx);
        split_vector(&hf->prefixes, &new_cont->prefixes, split_idx);
        split_vector(&hf->idx_types, &new_cont->idx_types, split_idx);

        // update frame sizes by looping over headers in new frame
        for (int i = 0; i < new_cont->hdr_pairs.size(); ++i) {
            size_t sz = hdr_sz(&new_cont->hdr_pairs[i], new_cont->idx_types[i]);
            f->len -= sz;
            new_cont->len += sz;
        }

        // add new frame to stream and return
        this->strm_->insert(this->strm_->begin() + frm_idx + 1, new_cont);
        strm_sz_ += HDRSZ;
        return 1;
    }

    /** Performs random bit mutation on the Headers fields of the given Frame */
    virtual size_t mutate_headers(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *hf = dynamic_cast<Headers *>(f);
        hf->reset_srlz_blk();

        if (hf->hdr_pairs.empty()) {
            return 0;
        }

        unsigned int idx = my_rand(hf->hdr_pairs.size());

        std::set<HPacker::KeyValuePair> nv_pairs;
        std::set<std::string> names;
        headers_in_table(nv_pairs, names, f, idx);

        size_t sz;  // maximum possible size increase by applying given mutation
        switch (fr.field) {
            case FrameField::Name:
                return mutate_name(f, idx, MaxSize, m, nv_pairs, names);
            case FrameField::Value:
                return mutate_value(f, idx, MaxSize, m, nv_pairs);
            case FrameField::Encoding:
                return mutate_encoding(f, idx, MaxSize, nv_pairs, names);
            case FrameField::Dup:
                sz = hdr_sz(&hf->hdr_pairs[idx], hf->idx_types[idx]);  // get ACTUAL size with idx type
                if (strm_sz_ + sz <= MaxSize) {
                    hf->hdr_pairs.insert(hf->hdr_pairs.begin() + idx, hf->hdr_pairs[idx]);
                    hf->prefixes.insert(hf->prefixes.begin() + idx, hf->prefixes[idx]);
                    hf->idx_types.insert(hf->idx_types.begin() + idx, hf->idx_types[idx]);
                    f->len += sz;
                    strm_sz_ += sz;
                    return 1;
                }
                break;
            case FrameField::Swap:
                return swap_headers(f, idx, MaxSize);
            case FrameField::Delete:
                return delete_header(f, idx, nv_pairs, names);
            case FrameField::Split:
                return split_headers(f, MaxSize);
            default:
                std::cout << "Invalid field for SettingsFrame" << std::endl;
        }
        return 0;
    }

    /** Adjusts the given Padded frame's actual padding vector to be the size of its current padlen field */
    void adjust_padded(Frame *f, unsigned int allowed_size) {
        auto *pf = dynamic_cast<Padded *>(f);

        // ensure that new value is within allowed range
        // NOTE padlen is uint8_t -> max=255, so won't take up entire MaxSize
        if (pf->padlen > allowed_size) {
            pf->padlen = allowed_size;
        }

        // resize padding to match field
        f->len -= pf->padding.size();
        strm_sz_ -= pf->padding.size();
        pf->padding.resize(pf->padlen, 0); // resize to match padlen, with zeros if growing
        f->len += pf->padlen;
        strm_sz_ += pf->padlen;
    }

    /** Performs random bit mutation on the Padded fields of the given Frame */
    virtual size_t mutate_padded(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        auto *pf = dynamic_cast<Padded *>(f);

        unsigned int allowed_size = MaxSize - strm_sz_ + pf->padlen; // add back padding being mutated

        // padlen is an 8-bit field, so we can't extend padding beyond that
        if (allowed_size > UINT8_MAX) {
            allowed_size = UINT8_MAX;
        }

        switch (fr.field) {
            case Length:
                // mutate the pad length field (just an 8-bit int)
                m(&pf->padlen, sizeof(pf->padlen), sizeof(pf->padlen));
                adjust_padded(f, allowed_size);
                return 1;
            case Padding:
                if (allowed_size > 0) {
                    size_t ret = mutate_vector_(&pf->padding, f, allowed_size, m);
                    if (ret) {
                        pf->padlen = pf->padding.size();
                    }
                    return ret;
                }
            case PadFlag:
                if (f->flags & FLAG_PADDED) {
                    f->flags &= ~FLAG_PADDED;

                    // new space created by removing padding
                    f->len -= 1 + pf->padlen;
                    strm_sz_ -= 1 + pf->padlen;
                    return 1;
                } else if (allowed_size > 0) {
                    // must have at least one byte for padlen
                    f->flags |= FLAG_PADDED;

                    // new space taken by padlen
                    f->len++;
                    strm_sz_++;
                    allowed_size--;

                    // adjust padlen and actual padding based on allowed bounds
                    adjust_padded(f, allowed_size);
                    return 1;
                }
                break;
            default:
                std::cout << "Invalid field for Padded" << std::endl;
        }
        return 0;
    }

    virtual size_t mutate_headersframe(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        unsigned int allowed_size = MaxSize - strm_sz_;

        switch (fr.field) {
            case PriorityFlag:
                if (f->flags & FLAG_PRIORITY) {
                    f->flags &= ~FLAG_PRIORITY;

                    // new space created by removing priority
                    f->len -= 5;
                    strm_sz_ -= 5;
                    return 1;
                } else if (allowed_size >= 5) {
                    f->flags |= FLAG_PRIORITY;

                    // new space taken by weight/dependency
                    f->len += 5;
                    strm_sz_ += 5;
                    return 1;
                }
                break;
            default:
                std::cout << "Invalid field for HeadersFrame" << std::endl;
        }
        return 0;
    }

    virtual size_t mutate_priorityframe(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        // does nothing because PriorityFrame is just DepWeight
        return 0;
    }

    virtual size_t mutate_continuation(const FieldRep &fr, Frame *f, Mutator m, unsigned int MaxSize) {
        // does nothing because Continuation is just Headers
        return 0;
    }

    std::minstd_rand *rnd_ = nullptr;  // shared RNG
    uint64_t strm_sz_ = 0;
};

#endif
