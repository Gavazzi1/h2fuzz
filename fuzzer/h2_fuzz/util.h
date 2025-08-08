#ifndef H2SRLZ_UTIL_H
#define H2SRLZ_UTIL_H

class Util {
  public:
    /**
     * Converts the given integer value to a hex representation as a string
     * From https://stackoverflow.com/questions/5100718/integer-to-hex-string-in-c
     */
    static std::string to_hex(unsigned int val) {
        std::stringstream ss;
        ss << std::hex << val;
        return "0x" + ss.str();
    }

    static bool is_ws(char c) {
        return c == ' ' || c == '\t';
    }

    /**
     * Returns whether the given string "val" equals the target string, but with optional whitespace and special
     * characters before and/or after it.
     *
     * Note that this should only be used for target strings that begin and end with alphanumeric characters
     */
    static bool special_match(const std::string &val, const std::string &target) {
        if (val.length() > INT64_MAX || val.length() < target.length()) {
            // quick bounds check. let's just assume this won't happen
            return false;
        }

        int64_t sidx = -1;
        int64_t eidx = -1;

        for (int64_t i = 0; i < val.length(); ++i) {
            if (!is_ws(val[i])) {
                sidx = i;
                break;
            }
        }

        for (int64_t j = val.length() - 1; j >= 0; --j) {
            if (!is_ws(val[j])) {
                eidx = j;
                break;
            }
        }

        if (eidx - sidx != target.length()-1) {
            return false;
        }

        return val.substr(sidx, target.length()) == target;
    }

    /** Compares two string pointers for equality */
    static bool str_ptr_equals(std::string *first, std::string *second) {
        // one-liner that's harder to read
        //return ((first == nullptr) == (second == nullptr)) && ((first == second) || (*first == *second));

        if ((first == nullptr) != (second == nullptr)) {
            return false;  // make sure either both are null or both are not null
        } else if (first == second) {
            return true;  // check if both are null
        } else {
            return *first == *second;  // both not null, so dereference and compare
        }
    }
};

#endif
