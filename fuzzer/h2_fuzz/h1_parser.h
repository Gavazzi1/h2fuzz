#ifndef NEZHA_H1_PARSER_H
#define NEZHA_H1_PARSER_H

#include <string>
#include <vector>
#include <cstring>

/**
 * Parser object for converting an HTTP/1 request in a buffer
 * into its request line, headers, and body_str
 */
struct H1Parser {
    H1Parser() = default;

    ~H1Parser() {
        delete this->reqline;
        delete this->body;
        for (auto *el : this->headers) {
            delete el;
        }
    }

    /**
     * Parses this H1Parser object from the HTTP/1 request in the given buffer "buf" of size "sz"
     */
    void parse(const char *buf, size_t sz) {
        size_t s_idx = 0;
        size_t e_idx = 0;
        bool seen_cr = false;

        for (int i = 0; i < sz; ++i) {
            // check if this is a CRLF
            if (seen_cr && buf[i] == '\n') {
                --e_idx;  // decrement so that we don't include \r

                // copy line into its own new array
                size_t line_sz = e_idx - s_idx;
                char line[line_sz];
                memcpy(line, buf + s_idx, line_sz);

                // first check to add reqline_str
                if (this->reqline == nullptr) {
                    this->reqline = new std::string(line, line_sz);
                }
                else if (e_idx == s_idx) {
                    // if we just read a /r/n, s_idx will be the index of the \r
                    // next check if this was the double \r\n that signals the end of headers
                    size_t body_sz = sz - (e_idx + 2);
                    char body_arr[body_sz];
                    memcpy(body_arr, buf + e_idx + 2, body_sz);
                    this->body = new std::string(body_arr, body_sz);
                    return;
                }
                else {
                    // otherwise this is a header
                    this->headers.push_back(new std::string(line, line_sz));
                }

                s_idx = e_idx + 2; // right now, e_idx is on the \n, so new start idx is next byte
                e_idx = s_idx;
                seen_cr = false;
            }
            else {
                // otherwise, check if this is a \r and increment the end index
                seen_cr = buf[i] == '\r';
                ++e_idx;
            }
        }
    }

    std::string *reqline = nullptr;
    std::vector<std::string *> headers;
    std::string *body = nullptr;
};

#endif
