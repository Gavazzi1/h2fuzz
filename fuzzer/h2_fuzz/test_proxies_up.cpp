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

int main(int argc, char** argv) {
    HashComp* ret_vals[16];
    uint8_t Data[4096];
    uint32_t Size;

    if (argc == 1) {
        HeadersFrame hf;
        hf.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
        hf.stream_id = 0x00000001;
        auto npref = hpack::HPacker::PrefixType::LITERAL_HEADER_WITHOUT_INDEXING;
        auto nidx = hpack::HPacker::IndexingType::NONE;
        hf.add_header(":method", "GET",npref, nidx);
        hf.add_header(":scheme", "https",npref, nidx);
        hf.add_header(":path", "/",npref, nidx);
        hf.add_header(":authority", GRAMMAR_AUTH,npref, nidx);
        hpack::HPacker hpe;
        Size = hf.serialize((char*)Data, 4096, &hpe, false);
    } else {
        std::ifstream is(argv[1], std::ifstream::binary);
        auto *strm = Deserializer::deserialize_stream(is);
        Size = strm->serialize((char*)Data, 4096);
        for (auto f : *strm) {
            delete f;
        }
        delete strm;
    }

    std::cout << "Successfully obtained and serialized test input. Launching threads." << std::endl;
    LAUNCH(t_nginx, "nginx", "172.17.0.3", 0)
    LAUNCH(t_caddy, "caddy", "172.17.0.4", 1)
    LAUNCH(t_apache, "apache", "172.17.0.5", 2)
    LAUNCH(t_envoy, "envoy", "172.17.0.6", 3)
    LAUNCH(t_haproxy, "haproxy", "172.17.0.7", 4)
    LAUNCH(t_traefik, "traefik", "172.17.0.8", 5)
    LAUNCH(t_varnish, "varnish", "172.17.0.9", 6)
    LAUNCH(t_h2o, "h2o", "172.17.0.10", 7)
    LAUNCH(t_ats, "ats", "172.17.0.11", 8)
    LAUNCH(t_akamai, "akamai", "172.17.0.12", 9)
    LAUNCH(t_cloudflare, "cloudflare", "172.17.0.13", 10)
    LAUNCH(t_cloudfront, "cloudfront", "172.17.0.14", 11)
    LAUNCH(t_fastly, "fastly", "172.17.0.15", 12)
    LAUNCH(t_nghttp2, "nghttp2", "172.17.0.16", 13)
    LAUNCH(t_ols, "openlitespeed", "172.17.0.17", 14)
    LAUNCH(t_azure, "azure", "172.17.0.18", 15)

    CLEAN(t_nginx)
    CLEAN(t_caddy)
    CLEAN(t_apache)
    CLEAN(t_envoy)
    CLEAN(t_haproxy)
    CLEAN(t_traefik)
    CLEAN(t_varnish)
    CLEAN(t_h2o)
    CLEAN(t_ats)
    CLEAN(t_akamai)
    CLEAN(t_cloudflare)
    CLEAN(t_cloudfront)
    CLEAN(t_fastly)
    CLEAN(t_nghttp2)
    CLEAN(t_ols)
    CLEAN(t_azure)

    std::vector<std::string> proxies = {"nginx", "caddy", "apache", "envoy", "haproxy", "traefik", "varnish",
                                        "h2o", "ats", "akamai", "cloudflare", "cloudfront", "fastly",
                                        "nghttp2", "openlitespeed", "azure"};
    bool all_good = true;
    for (int i = 0; i < proxies.size(); ++i) {
        if (ret_vals[i] == nullptr) {
            all_good = false;
        } else if (ret_vals[i]->noresp_err) {
            std::cout << proxies[i] << " signaled a no-response error " << ret_vals[i]->status << std::endl;
            all_good = false;
        }
    }

    if (all_good) {
        std::cout << "All proxies returned status 200" << std::endl;
    }

    ProxyConfig::clear_cache();
    std::string h1reqs;
    for (auto hc : ret_vals) {
        h1reqs += hc->to_filedata();
        h1reqs += "----------\n";
        delete hc;
    }

    std::ofstream outfd("fwd_reqs.txt");
    if (outfd.is_open()) {
        outfd << h1reqs;
        outfd.close();
        std::cout << "Wrote forwarded requests to fwd_reqs.txt" << std::endl;
    } else {
        std::cout << "Could not open fwd_reqs.txt for writing" << std::endl;
    }
}
