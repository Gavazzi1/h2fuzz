#include "callbacks.h"
#include <iostream>
#include <cerrno>
#include "h1_parser.h"
#include "../h2_serializer/src/deserializer.h"
#include "proxy_config.h"
#include "hashcomp.h"
#include "client.h"
#include "../debug.h"


void error(const char *msg) { perror(msg); exit(0); }

void del_stream(H2Stream *strm) {
    if (strm == nullptr) {
        return;
    }
    for (auto f : *strm) {
        delete f;
    }
    delete strm;
}

size_t preprocess_req(const ProxyConfig &filt, const uint8_t *Data, size_t Size, char **new_data) {
    membuf sbuf((char*)Data, (char*)Data + Size);
    std::istream in(&sbuf);
    H2Stream* h2strm = Deserializer::deserialize_stream((char*)Data, Size);

    // search for headers and replace :authority header value with a unique value for this proxy
    int n_auth = 0;
    for (auto f : *h2strm) {
        if (Frame::has_headers(f)) {
            auto *hdrs = dynamic_cast<Headers*>(f);
            for (int i = 0; i < hdrs->hdr_pairs.size(); ++i) {
                auto &h = hdrs->hdr_pairs[i];
                DEBUG("header: " << h.first << ":" << h.second << " " << (int)hdrs->prefixes[i] << "/" << (int)hdrs->idx_types[i])
                if (h.first == ":authority" || h.first == ":path" || Util::special_match(h.first, "host")) {
                    DEBUG("overwriting authority value " << h.first << " --> " << filt.authority)
                    size_t host_pos = h.second.find(GRAMMAR_AUTH);
                    if (host_pos != std::string::npos) {
                        h.second.replace(host_pos, strlen(GRAMMAR_AUTH), filt.authority);
                    }
                    ++n_auth;
                }
            }
        }
    }

    // allocate enough space for every modified header
    size_t size_plus_auth_changes = Size + n_auth * filt.authority.length();
    char *mut_data = new char[size_plus_auth_changes];
    size_t newsz = h2strm->serialize(mut_data, size_plus_auth_changes);
    del_stream(h2strm);
    *new_data = mut_data;  // pass pointer back to callback
    return newsz;
}

HashComp *callback(const char *addr, int port, const ProxyConfig &filt, const uint8_t *Data, size_t Size) {
    DEBUG("in callback")
    Client c;
    DEBUG("connecting")

    // try connecting forever -- hard assumption that the proxy is up and will never die
    int conn_ret = -1;
    int iter = 0;
    while (conn_ret != 0) {
        if (iter == 10) {
            std::cerr << "Failed connecting to " << addr << " 10 times in a row" << std::endl;
            iter = 0;
        }

        conn_ret = c.connect(addr, port);
        ++iter;
    }

    // preprocess -- modify outgoing authority header
    char *mut_data;
    DEBUG("preprocessing request. data size= " << Size << " and new buffer size=" << Size + filt.authority.length())
    Size = preprocess_req(filt, Data, Size, &mut_data);
    DEBUG("preprocessed request")

    // send data to proxy
    ssize_t send_sz = c.send(mut_data, Size, 0);
    DEBUG("sent " << send_sz << " bytes and errno=" << errno)
    delete[] mut_data;

    std::vector<char> full_resp;
    full_resp.reserve(4096);
    char buf[4096];
    ssize_t resp_sz = 0;
    while (true) {
        ssize_t amt_read = c.read(buf, sizeof(buf));
        DEBUG("read " << amt_read << " bytes and errno=" << errno)
        if (amt_read == -1 || amt_read == 0) {
            break;  // timeout or done reading
        } else {
            resp_sz += amt_read;
            full_resp.insert(full_resp.end(), buf, buf + amt_read);
        }
    }
    DEBUG("in total read " << resp_sz << " bytes and errno=" << errno)
    bool timeout = resp_sz == -1 && errno == EAGAIN;

    int closeval = c.close();
    DEBUG("close returned " << closeval << " and errno=" << errno)

    // read response and deserialize to H2 stream
    H2Stream* h2strm = Deserializer::deserialize_stream(full_resp.data(), resp_sz);

    bool data_found = false;
    std::string status;
    std::string alldata;
    uint32_t goaway_err = 0;
    uint32_t rst_stream_err = 0;

    // parse out response code and all data from DataFrames
    for (auto f : *h2strm) {
        if (Frame::has_headers(f)) {
            DEBUG("header frame")
            auto *hf = dynamic_cast<Headers*>(f);
            for (const auto& hdr : hf->hdr_pairs) {
                DEBUG(hdr.first << " = " << hdr.second)
                if (hdr.first == ":status") {
                    DEBUG("found status")
                    status = hdr.second;
                    break;
                }
            }
        }
        else if (f->type == DATA) {
            DEBUG("data frame")
            data_found = true;
            auto *df = dynamic_cast<DataFrame*>(f);
            alldata += std::string(df->data.data(), df->data.size());  // string works as a stringbuilder
        }
        else if (f->type == GOAWAY) {
            auto *ga = dynamic_cast<GoAway*>(f);
            goaway_err = ga->error_code;
        }
        else if (f->type == RST_STREAM ) {
            auto *rsf = dynamic_cast<RstStreamFrame*>(f);
            rst_stream_err = rsf->error_code;
        }
        else {
            DEBUG("frame was not interesting")
        }
    }

    // reclaim memory
    del_stream(h2strm);

    auto *hc = new HashComp();
    hc->noresp_err = timeout || goaway_err != 0 || rst_stream_err != 0;
    // hc->status = status; // NOTE: removing this b/c most diffs are variations on error codes. also nondeterministic
    if ((status.empty() || status == "200") && data_found) {
        DEBUG("found status and data")

        // special case Azure -- returns status 200 with an error body
        if (alldata.rfind("<!DOCTYPE", 0) == 0) {
            hc->noresp_err = true;
        } else {
            // compute hash of request data (presumably an HTTP/1 request)
            // parse and process h1 request
            H1Parser hp;
            hp.parse(alldata.data(), alldata.length());

            // extract hashable components as strings, then hash them
            hc->orig = alldata;  // to pass original request to Fuzzer core
            hc->parse(hp, filt);
            hc->hash_indiv();
        }

#if DBG_MODE
        hc->print_unif();
#endif
    } else {
        DEBUG("Bad status or no DataFrame. Status=" << status << " DataFrame=" << data_found)
        hc->noresp_err = true;  // anything that isn't 200 error is considered a non-response
#if DBG_MODE
        hc->print_unif();
#endif
    }
    return hc;
}
