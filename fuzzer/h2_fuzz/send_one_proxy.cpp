/**
 * Utility program for sending an HTTP/2 stream from a BINARY FILE to a given proxy.
 *
 * Functionality is otherwise essentially the same as build_and_send_stream.cpp
 */

#include <cstdint>
#include <cstddef>
#include <thread>
#include <vector>
#include <iostream>

#include "callbacks.h"
#include "../h2_serializer/src/frames/frames.h"
#include "../h2_serializer/src/deserializer.h"

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
        std::cout << "Usage: ./send_one_proxy <proxy_name> <file_name>" << std::endl;
        return 1;
    }

    char *pname = argv[1];
    char *fn = argv[2];

    std::map<std::string, std::string> ips = {
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
    };

    auto it = ips.find(pname);
    if (it == ips.end()) {
        std::cout << "Invalid proxy" << std::endl;
        return 1;
    }

    std::ifstream is(fn, std::ifstream::binary);
    auto *strm = Deserializer::deserialize_stream(is);
    Size = strm->serialize((char *) Data, 4096);
    for (auto f: *strm) {
        delete f;
    }
    delete strm;

    LAUNCH(t_name, argv[1], it->second.c_str(), 0)
    CLEAN(t_name)

    for (auto hc: ret_vals) {
        if (hc != nullptr) {
            std::cout << hc->to_filedata();
        }
    }

    return 0;
}
