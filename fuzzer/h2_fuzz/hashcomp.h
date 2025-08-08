#ifndef NEZHA_HASHCOMP_H
#define NEZHA_HASHCOMP_H

#include <iostream>
#include <string>
#include <algorithm>
#include <sstream>
#include "chunkparser.h"
#include "hash_utils.h"
#include "h1_parser.h"
#include "proxy_config.h"
#include "../debug.h"
#include "util.h"

#define PROC_SPECIAL_HDR(HDR_NAME, STR_VAL, VEC_VAL) else if (name == HDR_NAME) { \
                                                         if (STR_VAL == nullptr) { \
                                                             STR_VAL = new std::string(val); \
                                                         } else { \
                                                             concat_and_add_header(name, val, VEC_VAL); \
                                                         } \
                                                     } else if (Util::special_match(name, HDR_NAME)) { \
                                                         concat_and_add_header(name, val, VEC_VAL); \
                                                     }

/**
 * Struct of all fields comprising the hash
 */
struct HashComp {
    HashComp() = default;

    // fields that are set EXPLICITLY by the fuzzer itself
    bool noresp_err = false;
    std::string status;
    std::string orig;  // original request so that Fuzzer core can use it

    // string values of certain fields parsed out by this object
    std::string *reqline_str = nullptr;
    std::string *host_str = nullptr;
    std::vector<std::string> rem_host_str;
    std::string *cl_str = nullptr;
    std::vector<std::string> rem_cl_str;
    std::string *te_str = nullptr;
    std::vector<std::string> rem_te_str;
    std::string *conn_str = nullptr;
    std::vector<std::string> rem_conn_str;
    std::string *expect_str = nullptr;
    std::vector<std::string> rem_expect_str;
    std::string *body_str = nullptr;

    // computed hash values
    size_t version_hash = 0;
    size_t method_hash = 0;
    size_t host_hash = 0;       // Host
    size_t rem_host_hash = 0;
    size_t cl_hash = 0;         // Content-Length
    size_t rem_cl_hash = 0;
    size_t te_hash = 0;         // Transfer-Encoding
    size_t rem_te_hash = 0;
    size_t conn_hash = 0;       // Connection
    size_t rem_conn_hash = 0;
    size_t expect_hash = 0;     // Expect
    size_t rem_expect_hash = 0;
    size_t body_hash = 0;
    int chnk_err = 0;  // note that this MAY need to be assigned
    int extra_data = 0; // assigned manually

    /**
     * Returns the string representation of this hashcomp's data that should be stored in a *_h1_* file in /out
     * This includes any error signals and the original http/1 request itself
     */
    std::string to_filedata() const {
        std::string out;
        out += (noresp_err ? "1" : "0");
        out += ";" + this->status;
        out += ";" + std::to_string(this->chnk_err) + "\n";
        out += this->orig;
        return out;
    }

    /**
     * Extracts the hash components from the given H1Parser object
     */
    void parse(const H1Parser &hp, const ProxyConfig &filter) {
        cleanup();
        DEBUG("hashcomp -- parsing and ignoring " << filter.headers.size() << " headers")

        if (hp.reqline != nullptr) {
            this->reqline_str = new std::string(*hp.reqline);
        }

        // now parse out headers
        for (auto h : hp.headers) {
            // name is everything up to first colon
            size_t col = h->find(':');
            if (col == std::string::npos) {
                continue;
            }

            // extract name
            char name_buf[col];
            for (int i = 0; i < col; ++i) {
                name_buf[i] = (char) tolower(h->at(i));  // always compare lowercase
            }
            std::string name(name_buf, col);
            std::string val = h->substr(col + 1, h->length() - col);
            DEBUG("hashcomp -- checking header: " << name << " = " << val)

            // Match header name to list of well-known headers we care about
            if (filter.headers.find(name) != filter.headers.end()) {
                // first check if we need to filter out header. faster since most headers are filtered
                DEBUG("in hashcomp, header " << name << " filtered out")
                continue;
            } else if (name == "host") {
                // normalize host name by replacing known host value with localhost
                // TODO why do we do this again?
                patch_host_value(val, filter);

                if (this->host_str == nullptr) {
                    this->host_str = new std::string(val);
                } else {
                    concat_and_add_header(name, val, this->rem_host_str);
                }
            } else if (Util::special_match(name, "host")) {
                patch_host_value(val, filter);
                concat_and_add_header(name, val, this->rem_host_str);
            }
            PROC_SPECIAL_HDR("content-length", this->cl_str, this->rem_cl_str)
            PROC_SPECIAL_HDR("transfer-encoding", this->te_str, this->rem_te_str)
            PROC_SPECIAL_HDR("connection", this->conn_str, this->rem_conn_str)
            PROC_SPECIAL_HDR("expect", this->expect_str, this->rem_expect_str)
        }

        // quit early if parser somehow didn't find a body (e.g., empty string, or no double CRLF at the end)
        if (hp.body == nullptr || hp.body->empty()) {
            return;
        }

        // now handle request body_str
        if (this->te_str != nullptr && Util::special_match(*this->te_str, "chunked")) {
            ChunkParser pars{};
            int n_read = pars.parse_chunked(hp.body->c_str(), hp.body->length());
            this->chnk_err = pars.err;
            this->body_str = new std::string(pars.body);

            // append any lingering body_str such as trailer headers or extraneous chunks
            if (n_read < hp.body->length()) {
                this->extra_data = 1;
                this->body_str->append(hp.body->substr(n_read, this->body_str->length() - n_read));
            }

            return;
        }

        this->body_str = new std::string(*hp.body);
    }

    ~HashComp() {
        cleanup();
    }

    void cleanup() {
        delete reqline_str;
        delete host_str;
        delete cl_str;
        delete te_str;
        delete body_str;
    }

    /**
     * Printer utility function
     */
    void print_unif() const {
        std::cout << "no response?: " << noresp_err << std::endl;
        std::cout << "chunk error: " << chnk_err << std::endl;
        std::cout << "version: " << version_hash << " " << (reqline_str != nullptr ? *reqline_str : "null") << std::endl;
        std::cout << "host: " << host_hash << " " << (host_str != nullptr ? *host_str : "null") << std::endl;
        std::cout << "content-length: " << cl_hash << " " << (cl_str != nullptr ? *cl_str : "null") << std::endl;
        std::cout << "transfer-encoding: " << te_hash << " " << (te_str != nullptr ? *te_str : "null") << std::endl;
        //std::cout << "remaining: " << remain_hash << std::endl;
        //for (auto &h : remain_str) {
        //    std::cout << "\t" << h << std::endl;
        //}
        std::cout << "body: " << body_hash << " " << (body_str != nullptr ? *body_str : "null") << std::endl;
    }

    /** State of algorithm to hash the path separately from the rest */
    enum RLHashState {
        Space1, Method, Space2, Path, Version
    };

    /**
     * Hash the host header, which may be a comma-separated list of host values
     *
     * Because some proxies automatically convert invalid host values to "localhost",
     * we separate non-localhost strings, convert to lowercase, and normalize
     * to avoid differences exploding (e.g., 9000+ diffs in a 72 hour experiment)
     */
    void hash_host() {
        if (this->host_str == nullptr) {
            this->host_hash = 0;
            this->rem_host_hash = 0;
            return;
        }

        // tokenize with comma as the delimiter
        std::stringstream ss(*this->host_str);
        std::string token;
        while (getline(ss, token, ',')) {
            if (token == " localhost" || token == "localhost") {
                // localhost handled as normal
                // keep this here so there's a distinction between this and requests with no host at all
                this->host_hash = HashUtils::checksum(&token);
            } else {
                // other values are converted to lowercase and stored in "extra_hosts"
                char lc_buf[token.length()];
                for (int i = 0; i < token.length(); ++i) {
                    lc_buf[i] = (char) tolower(token.at(i));  // always compare lowercase
                }
                std::string lc_host(lc_buf, token.length());

                rem_host_str.push_back("host:" + lc_host);
            }
        }

        // then, checksum all strings
        this->rem_host_hash = HashUtils::checksum(this->rem_host_str);
    }

    /**
     * Computes hashes of each component in this HashComp
     */
    void hash_indiv() {
        // start with request line (parse path separate from rest)
        this->version_hash = 0;
        this->method_hash = 0;
        RLHashState state = Space1; // start by parsing whitespace at the beginning of request

        if (this->reqline_str != nullptr) {
            for (char c: *this->reqline_str) {
                if (state == Space1 && !isspace(c)) {
                    // seen start of method
                    state = Method;
                } else if (state == Method && isspace(c)) {
                    // method over, read whitespace before path
                    state = Space2;
                } else if (state == Space2 && !isspace(c)) {
                    // found path, start adding to out->path
                    state = Path;
                } else if (state == Path && isspace(c)) {
                    // path over, everything else is the version
                    state = Version;  // no longer in FSM
                }

                // new approach: parse Method as path so that it gets normalized and parse Version (version) as reqline
                if (state == Method) {
                    this->method_hash += c;
                } else if (state == Version) {
                    this->version_hash += c;
                }
            }
        }

        // headers just checksummed
        this->hash_host();
        this->cl_hash = HashUtils::checksum(this->cl_str);
        this->te_hash = HashUtils::checksum(this->te_str);
        this->conn_hash = HashUtils::checksum(this->conn_str);
        this->expect_hash = HashUtils::checksum(this->expect_str);

        // containers are also checksummed
        this->rem_cl_hash = HashUtils::checksum(this->rem_cl_str);
        this->rem_te_hash = HashUtils::checksum(this->rem_te_str);
        this->rem_conn_hash = HashUtils::checksum(this->rem_conn_str);
        this->rem_expect_hash = HashUtils::checksum(this->rem_expect_str);

        // body_str just a regular checksum for now
        this->body_hash = HashUtils::checksum(this->body_str);
    }

    /**
     * Hashes this HashComp to a single value for direct comparison by the fuzzer
     *
     * Note that at present, nezha expects integer return values, so we must hash to an int, not a size_t
     * TODO make nezha work with size_t?
     */
    int hash_full() {
        std::vector<int> vec;
        vec.push_back(noresp_err);
        vec.push_back(reqline_str != nullptr);  // no path vs path normed to zero
        vec.push_back(method_hash);
        vec.push_back(version_hash);
        vec.push_back(host_hash);
        vec.push_back(!rem_host_str.empty());  // no extra host vals vs extra host vals normed to zero
        vec.push_back(rem_host_hash);
        vec.push_back(cl_str != nullptr);  // no CL vs CL normed to zero
        vec.push_back(cl_hash);
        vec.push_back(!rem_cl_str.empty());
        vec.push_back(rem_cl_hash);
        vec.push_back(te_hash);
        vec.push_back(!rem_te_str.empty());
        vec.push_back(rem_te_hash);
        vec.push_back(conn_hash);
        vec.push_back(!rem_conn_str.empty());
        vec.push_back(rem_conn_hash);
        vec.push_back(expect_hash);
        vec.push_back(!rem_expect_str.empty());
        vec.push_back(rem_expect_hash);
        vec.push_back(body_str != nullptr);  // no body vs body normed to zero
        vec.push_back(body_hash);
        vec.push_back(chnk_err);

        // hash function for vector of integers
        // from https://stackoverflow.com/questions/20511347/a-good-hash-function-for-a-vector/72073933#72073933
        // TODO make this work for 64 bit
        int seed = vec.size();
        for (auto x: vec) {
            x = ((x >> 16) ^ x) * 0x45d9f3b;
            x = ((x >> 16) ^ x) * 0x45d9f3b;
            x = (x >> 16) ^ x;
            seed ^= x + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
        return seed;
    }

    bool operator==(const HashComp &other) const {
        if (this->noresp_err != other.noresp_err ||
            this->status != other.status ||
            !Util::str_ptr_equals(this->reqline_str, other.reqline_str) ||
            !Util::str_ptr_equals(this->host_str, other.host_str) ||
            this->rem_host_str.size() != other.rem_host_str.size() ||
            !Util::str_ptr_equals(this->cl_str, other.cl_str) ||
            !Util::str_ptr_equals(this->te_str, other.te_str) ||
            //this->remain_str.size() != other.remain_str.size() ||
            !Util::str_ptr_equals(this->body_str, other.body_str) ||
            this->chnk_err != other.chnk_err) {
            return false;
        }
        // check remaining headers in their own loop
        //for (int i = 0; i < this->remain_str.size(); ++i) {
        //    if (this->remain_str[i] != other.remain_str[i]) {
        //        return false;
        //    }
        //}
        // check remaining hosts in their own loop
        for (int i = 0; i < this->rem_host_str.size(); ++i) {
            if (this->rem_host_str[i] !=  other.rem_host_str[i]) {
                return false;
            }
        }
        return true;
    }

    bool operator!=(const HashComp &other) const {
        return !(*this == other);
    }

protected:
    static void concat_and_add_header(const std::string &name, const std::string &val, std::vector<std::string> &vec) {
        std::string lc_hdr(name);
        lc_hdr.append(":");
        lc_hdr.append(val);
        vec.push_back(lc_hdr);
    }

    /**
     * Replace the known forwarded Host value with a constant string ("localhost") to enable difference detection
     * among proxies
     */
    static void patch_host_value(std::string &val, const ProxyConfig &filter) {
        size_t pos = val.find(filter.host);
        if (pos != std::string::npos) {
            val.replace(pos, filter.host.length(), "localhost");
        }
    }
};

#endif
