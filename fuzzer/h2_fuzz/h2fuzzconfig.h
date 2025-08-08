#pragma once

#include <libconfig.h++>
#include <map>
#include <vector>
#include "../h2_serializer/src/frames/common/baseframe.h"

enum FrameField {
    Length, Type, Flags, Reserved, StreamID, /* BaseFrame */
    Padding, PadFlag, /* Padded */
    Data, /* DataFrame */
    Exclusive, Weight, PriorityFlag, /* DepWeight */
    Name, Value, Encoding, /* Headers */
    ErrCode, /* RstStream */
    ID, /* Settings */
    Increment, /* WindowUpdate */
    Dup, Delete, Swap, Split /* Container types */
};

#define BASE 0xF0
#define DEPWEIGHT 0xF1
#define HDRS 0xF2
#define PAD 0xF3

#define ERR_CFG_FLD_NEXT (-1)
#define ERR_CFG_FLD_ISLIST (-2)
#define ERR_CFG_SET_ISPAIR (-3)
#define ERR_CFG_NOTSUPP (-4)
#define ERR_LKL_LOOKUP (-5)
#define ERR_LKL_SUM (-6)

/**
 * Represents the field to be mutated and the frame it originates from.
 * Yes, this means that data is duplicated between the Frame class and here,
 * but it's the only way I can think of to do this at this point.
 */
class FieldRep {
public:
    FieldRep(FrameField field, uint8_t frametype) {
        this->field = field;
        this->frametype = frametype;
    }

    FrameField field;
    uint8_t frametype;
};

class H2FuzzConfig {
public:
    H2FuzzConfig() = default;

    // set default values for easier testing
    unsigned int prob_bit = 20, prob_delete = 20, prob_dup = 20, prob_swap = 20, prob_fix = 20;
    unsigned int prob_add = 50, prob_splice = 50;
    unsigned int prob_do_hdr_set_mut = 50;

    int read_config(const std::string &fn) {
        c.readFile(fn.c_str());  // can throw exceptions. allow them to propagate

        int ret;
        ret = parse_mutable_fields();
        if (ret != 0) return ret;

        ret = parse_likelihoods();
        if (ret != 0) return ret;

        return 0;
    }

    std::vector<FieldRep> *get_fields(uint8_t frame_type) {
        auto pos = lookup.find(frame_type);
        if (pos != lookup.end()) {
            return pos->second;
        } else {
            return nullptr;
        }
    }

protected:
    libconfig::Config c;
    std::map<uint8_t, std::vector<FieldRep> *> lookup;

    // these maps are populated statically in h2fuzzconfig.cpp
    static const std::map<std::string, uint8_t> str2frametype_;
    static const std::map<std::string, FrameField> str2frmfld_;

    std::vector<FieldRep> datafrm_flds;
    std::vector<FieldRep> hdrfrm_flds;
    std::vector<FieldRep> priority_flds;
    std::vector<FieldRep> rst_stream_flds;
    std::vector<FieldRep> settings_flds;
    std::vector<FieldRep> push_prom_flds;
    std::vector<FieldRep> ping_flds;
    std::vector<FieldRep> goaway_flds;
    std::vector<FieldRep> win_up_flds;
    std::vector<FieldRep> cont_flds;

    static bool str2frmfld(const std::string &s, FrameField *ff) {
        auto pos = H2FuzzConfig::str2frmfld_.find(s);
        if (pos != H2FuzzConfig::str2frmfld_.end()) {
            *ff = pos->second;
            return true;
        } else {
            return false;
        }
    }

    static bool str2frametype(const std::string &s, uint8_t *frm_type) {
        auto pos = H2FuzzConfig::str2frametype_.find(s);
        if (pos != H2FuzzConfig::str2frametype_.end()) {
            *frm_type = pos->second;
            return true;
        } else {
            return false;
        }
    }

    /**
     * Reads the mutable fields of the frame type specified by the given "key" into the given vector "dst"
     */
    int read_one(const std::string &key, std::vector<FieldRep> *dst) {
        libconfig::Setting &mut_els = c.lookup("mutable_fields." + key);
        if (!mut_els.isList()) {
            return ERR_CFG_FLD_ISLIST;  // mutable fields is not a list
        }

        for (int i = 0; i < mut_els.getLength(); ++i) {
            libconfig::Setting &fr_setting = mut_els[i];
            if (!fr_setting.isList() || fr_setting.getLength() != 2) {
                return ERR_CFG_SET_ISPAIR;  // value is not a pair (FrameField, FrameType)
            }

            // convert the strings in the config file into a FrameField and frame type
            FrameField ff;
            uint8_t frm_type;
            bool success1 = str2frmfld(fr_setting[0], &ff);
            bool success2 = str2frametype(fr_setting[1], &frm_type);

            if (!success1 || !success2) {
                return ERR_CFG_NOTSUPP;  // either FrameField or FrameType not supported
            }

            // finally, add the FrameField and frame type to "dst"
            dst->emplace_back(ff, frm_type);
        }

        return 0;
    }

    /**
     * Parse the lists of mutable fields for each frame type
     */
    int parse_mutable_fields() {
        if (!c.exists("mutable_fields")) return ERR_CFG_FLD_NEXT;

        // we associate strings in the config file with 1) vectors of mutable fields and 2) the frame type macros
        // these 3 vectors must be the same size. the same index in all 3 corresponds to the same frame type
        std::vector<std::string> key_vec{
                "data", "headers", "priority", "rst_stream", "settings",
                "push_prom", "ping", "goaway", "win_update", "continuation"};
        std::vector<std::vector<FieldRep> *> fr_vec{
                &datafrm_flds, &hdrfrm_flds, &priority_flds, &rst_stream_flds, &settings_flds,
                &push_prom_flds, &ping_flds, &goaway_flds, &win_up_flds, &cont_flds};
        std::vector<uint8_t> type_vec{
                DATA, HEADERS, PRIORITY_TYPE, RST_STREAM, SETTINGS,
                PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION};

        // populate fr_vec with vectors of mutable fields
        // then, map the frame macros to their associated vector in "lookup"
        for (int i = 0; i < key_vec.size(); ++i) {
            int ret = read_one(key_vec[i], fr_vec[i]);
            if (ret != 0) {
                return ret;
            }
            lookup[type_vec[i]] = fr_vec[i];
        }

        return 0;
    }

    int parse_likelihoods() {
        if (!c.exists("likelihoods") ||
            !c.exists("likelihoods.mutate_operators") ||
            !c.exists("likelihoods.crossover_operators")) {
            return ERR_CFG_FLD_NEXT;
        }

        if (!c.lookupValue("likelihoods.mutate_operators.bit", prob_bit)) return ERR_LKL_LOOKUP;
        if (!c.lookupValue("likelihoods.mutate_operators.delete", prob_delete)) return ERR_LKL_LOOKUP;
        if (!c.lookupValue("likelihoods.mutate_operators.dup", prob_dup)) return ERR_LKL_LOOKUP;
        if (!c.lookupValue("likelihoods.mutate_operators.swap", prob_swap)) return ERR_LKL_LOOKUP;
        if (!c.lookupValue("likelihoods.mutate_operators.fix", prob_fix)) return ERR_LKL_LOOKUP;
        if (!c.lookupValue("likelihoods.crossover_operators.add", prob_add)) return ERR_LKL_LOOKUP;
        if (!c.lookupValue("likelihoods.crossover_operators.splice", prob_splice)) return ERR_LKL_LOOKUP;
        if (!c.lookupValue("likelihoods.mutate_hdr_settings", prob_do_hdr_set_mut)) return ERR_LKL_LOOKUP;

        if (prob_bit + prob_delete + prob_dup + prob_swap + prob_fix != 100) return ERR_LKL_SUM;
        if (prob_add + prob_splice != 100) return ERR_LKL_SUM;
        if (prob_do_hdr_set_mut > 100) return ERR_LKL_SUM;

        return 0;
    }
};