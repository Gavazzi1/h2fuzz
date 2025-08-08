#pragma once

#include "callbacks.h"

/**
 * Utility class for normalizing the return values of callback functions, which are vectors of HashComps
 */
class Normalizer {
public:
    /**
     * Normalize the given vector of HashReps by transforming certain key values like this:
     *  - multiply all values by the size of "hashes"
     *  - compute the mean of all existing values
     */
    static void normalize(HashComp **hashes, int n) {
        normalize_one(hashes, n, &HashComp::method_hash,
                      [](HashComp *hc) { return hc->reqline_str != nullptr; });
        normalize_one(hashes, n, &HashComp::rem_host_hash,
                      [](HashComp *hc) { return !hc->rem_host_str.empty(); });
        normalize_one(hashes, n, &HashComp::cl_hash,
                      [](HashComp *hc) { return hc->cl_str != nullptr && *hc->cl_str != " 0"; });
        normalize_one(hashes, n, &HashComp::rem_cl_hash,
                      [](HashComp *hc) { return !hc->rem_cl_str.empty(); });
        normalize_one(hashes, n, &HashComp::rem_te_hash,
                      [](HashComp *hc) { return !hc->rem_te_str.empty(); });
        normalize_one(hashes, n, &HashComp::rem_conn_hash,
                      [](HashComp *hc) { return !hc->rem_te_str.empty(); });
        normalize_one(hashes, n, &HashComp::rem_expect_hash,
                      [](HashComp *hc) { return !hc->rem_te_str.empty(); });
        normalize_one(hashes, n, &HashComp::body_hash,
                      [](HashComp *hc) { return hc->body_str != nullptr && !hc->body_str->empty(); });
    }

protected:
    /**
     * Normalize one member variable of each HashComp in the given vector "hashes"
     * The member variable to normalize is passed as a parameter to the template function
     * h_type is the hash member variable that will be normalized
     */
    template <typename HashType>
    static void normalize_one(HashComp **hashes, int n, HashType h_type, bool (*do_norm)(HashComp *hc)) {
        size_t sum = 0;
        size_t n_normed = 0;
        for (int i = 0; i < n; ++i) {
            HashComp *hc = hashes[i];
            if (do_norm(hc)) {
                sum += hc->*h_type;  // add first so that we don't have to divide by # elements to make it work
                ++n_normed;
            }
        }

        for (int i = 0; i < n; ++i) {
            HashComp *hc = hashes[i];
            if (do_norm(hc)) {
                // scale up by number of elements, then subtract the mean sum
                hc->*h_type = hc->*h_type * n_normed - sum;
            }
        }
    }
};
