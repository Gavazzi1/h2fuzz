#ifndef CHUNKED_H
#define CHUNKED_H

#include "../debug.h"

#define ERR(s, code) DEBUG(s) this->err = code; return code;

#define NOCHUNKLF (-1)
#define BADHEX (-2)
#define NOCHUNKCRLF (-3)
#define NODATA (-4)
#define NO_LAST_CHUNK (-5)
#define NOSIZECRLF (-6)
#define NOSIZELF (-7)

/**
 * Utility class for parsing chunked bodies
 *
 * Refer to RFC for expected format
 * https://datatracker.ietf.org/doc/html/rfc9112#section-7.1
 */
class ChunkParser {
public:
    ChunkParser() = default;
    ~ChunkParser() = default;

    int err = 0; // error signal for hashcomp
    
    /**
     * Parse the (presumably) chunked body in the given string and store the raw body into the "body"
     * member variable.
     *
     * Returns the number of bytes read from the input string.
     *
     * If an error is encountered, returns the number of bytes read before encountering the error and sets this->err to
     * the corresponding error code.
     */
    int parse_chunked(const char *input, size_t length) {
        this->err = 0;
        this->in = input;
        this->sz = length;
        this->in_idx = 0;

        this->body.clear();
        this->body.reserve(sz);
        this->extensions.clear();
        this->extensions.reserve(sz);

        while (true) {
            long chnk_sz = parse_size();
            if (chnk_sz < 0) { return in_idx; }

            int ret;
            if (chnk_sz == 0) {
                ret = parse_trailers();
                if (ret < 0) { return in_idx; }
            } else {
                ret = parse_body(chnk_sz);
                if (ret < 0) { return in_idx; }
            }

            ret = parse_crlf_after_chunk();
            if (ret < 0) { return in_idx; }

            if (chnk_sz == 0) {
                return in_idx;
            }
        }
    }

    std::string body;
    std::string extensions;
    
private:
    const char *in = nullptr;
    size_t sz = 0;
    int in_idx = 0;

    /**
     * Return whether the given char is bad whitespace (BWS) as defined in RFC
     * https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.3
     */
    static bool is_bws(char c) {
        return c == ' ' || c == '\t';
    }

    /**
     * Return the int value associated with the given hex character, or -1 if it fails
     */
    static int parse_hex(char c) {
        if ('0' <= c && c <= '9') {
            return c - '0';
        }
        else if ('a' <= c && c <= 'f') {
            // 'a' is 97 and needs to return 10
            return c - 'a' + 10;
        }
        else if ('A' <= c && c <= 'F') {
            // 'A' is 65 and needs to return 10
            return c - 'A' + 10;
        }
        else {
            return -1;
        }
    }

    int parse_trailers() {
        /* parse trailers based on https://www.rfc-editor.org/rfc/rfc9112#section-7.1.2
         
           chunked-body   = *chunk
                            last-chunk
                            trailer-section
                            CRLF

           chunk          = chunk-size [ chunk-ext ] CRLF
                            chunk-data CRLF
           chunk-size     = 1*HEXDIG
           last-chunk     = 1*("0") [ chunk-ext ] CRLF

           chunk-data     = 1*OCTET ; a sequence of chunk-size octets
           
           trailer-section   = *( field-line CRLF )
         */
        ////////////////////
        /////// TODO ///////
        ////////////////////
        return 0;
    }

    /**
     * Parse the chunk size from the "in" string.
     * That is, the integer value of the hex string starting at the current position up to the \r\n
     */
    long parse_size() {
        if (in_idx == sz) {
            ERR("reached end of input before parsing chunk size", NO_LAST_CHUNK);
        }

        long out = 0;
        bool seen_cr = false;
        bool extension = false;
        for (; in_idx < sz; ++in_idx) {
            char cur = in[in_idx];
            if (seen_cr) {
                if (cur != '\n') {
                    ERR("no newline after CR", NOSIZELF);
                }
                ++in_idx;  // increment past \n

                return out;
            }

            if (cur == '\r') {
                seen_cr = true;
            } else if (extension) {
                // this is part of the extension before the \r\n, so append to the extensions string
                this->extensions.push_back(cur);
            }
            else if (is_bws(cur) || cur == ';') {
                // chunk extension
                extension = true;
            }
            else {
                int hex = parse_hex(cur);
                if (hex == -1) {
                    ERR("could not parse hex char: " << cur, BADHEX);
                }
                out = out * 16 + hex;
            }
        }

        // reached end of input without \r\n
        ERR("reached end of input without a CRLF after chunk size", NOSIZECRLF)
    }

    /**
     * Read the number of bytes specified in the previous chunk size (chnk_sz) and append to the "body" member variable
     */
    int parse_body(uint64_t chnk_sz) {
        uint64_t n_read = 0;
        while (n_read != chnk_sz && in_idx < sz) {
            this->body.push_back(in[in_idx]);

            ++in_idx;
            ++n_read;
        }

        if (n_read != chnk_sz) {
            ERR("could not read the number of bytes in the chunk size", NODATA)
        }
        return 0;
    }

    /**
     * Parse an \r\n from the input string starting at the current position
     */
    int parse_crlf_after_chunk() {
        // if no space left to read a CRLF, error based on whether at least a CR is present
        if (in_idx > sz - 2) {
            if (in_idx == sz - 1 && in[in_idx] == '\r') {
                ERR("reading newline at end of input", NOCHUNKLF)
            } else {
                ERR("reading CRLF at end of input", NOCHUNKCRLF)
            }
        }

        // else, error if no CRLF
        if (in[in_idx] != '\r') {
            ERR("no CRLF after chunk", NOCHUNKCRLF)
        } else if (in[in_idx + 1] != '\n') {
            ERR("no newline after CR", NOCHUNKLF)
        }

        in_idx += 2;
        return 0;
    }
};

#endif
