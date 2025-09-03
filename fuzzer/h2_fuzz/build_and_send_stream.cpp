/**
 * Utility program for building streams programmatically and observing how specific proxies handle them.
 */

#include <cstdint>
#include <cstddef>
#include <thread>
#include <vector>
#include <iostream>

#include "callbacks.h"
#include "../h2_serializer/src/frames/frames.h"
#include "../h2_serializer/src/deserializer.h"

typedef hpack::HPacker::PrefixType PrefType;
typedef hpack::HPacker::IndexingType IdxType;


H2Stream* get_stream() {
    auto *hf = new HeadersFrame();
    hf->flags |= FLAG_END_STREAM;
    hf->stream_id = 1;
    hf->add_header(":method", "GET", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);
    hf->add_header(":scheme", "https", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);
    hf->add_header(":path", "/reqid=_REQID_", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);
    hf->add_header(":authority", "akamai.test.com", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

    auto *c = new Continuation();
    c->flags |= FLAG_END_HEADERS;
    c->stream_id = 1;
    c->add_header("host", "some-value", PrefType::LITERAL_HEADER_WITHOUT_INDEXING, IdxType::NONE);

    auto *strm = new H2Stream();
    strm->push_back(hf);
    strm->push_back(c);

    return strm;
}


void callback_helper(const char *prox, const char *addr, int port, const uint8_t *Data, size_t Size, HashComp **hc) {
    DEBUG("----- Working on " << prox << " -----")
    ProxyConfig *filt = ProxyConfig::get_proxy_config(prox);
    HashComp *out = callback(addr, port, *filt, Data, Size);
    *hc = out;
}

#define LAUNCH(tname, fname, addr, idx) std::thread tname(callback_helper, fname, addr, 9090, Data, Size, ret_vals + idx);
#define CLEAN(tname) tname.join();

int main(int argc, char **argv) {
    HashComp *ret_vals[11];
    for (auto & ret_val : ret_vals) {
        ret_val = nullptr;
    }
    uint8_t Data[4096];
    uint32_t Size;

    if (argc < 3) {
        std::cout << "Usage: ./send_one_proxy <proxy name> <ip address of target>" << std::endl;
        return 1;
    }

    /**
     * This is the IP address of the target proxy you'll be forwarding to.
     *
     * "sudo docker inspect <image ID> | grep IPA" will give you the IP address
     *
     * alternatively, if you use the ./runproxies.sh script in h2fuzzer, the proxies should take these IP addresses:
            {"nginx",         "172.17.0.3"},
            {"caddy",         "172.17.0.4"},
            {"apache",        "172.17.0.5"},
            {"envoy",         "172.17.0.6"},
            {"haproxy",       "172.17.0.7"},
            {"traefik",       "172.17.0.8"},
            {"varnish",       "172.17.0.9"},
            {"h2o",           "172.17.0.10"},
            {"ats",           "172.17.0.11"},
            {"nghttp2",       "172.17.0.12"},
            {"openlitespeed", "172.17.0.13"},
     */
    const char* pname = argv[1];
    const char* ip_addr = argv[2];


    H2Stream *strm = get_stream();
    Size = strm->serialize((char *) Data, 4096);
    for (auto f: *strm) {
        delete f;
    }
    delete strm;

    LAUNCH(t_name, pname, ip_addr, 0)
    CLEAN(t_name)

    for (auto hc: ret_vals) {
        if (hc != nullptr) {
            std::cout << hc->to_filedata();
            delete hc;
        }
    }
    ProxyConfig::clear_cache();

    return 0;
}
