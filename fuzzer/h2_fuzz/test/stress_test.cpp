#include "../proxy_config.h"
#include "test_mutator_common.h"
#include "libfuzzer_mutator.h"
#include "../callbacks.h"
#include <thread>

Random *r;

size_t llvm_mutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    //Random r(0);
    LibFuzz_Mut lfm(*r);
    return lfm.DefaultMutate(Data, Size, MaxSize);
}

void mutate_stress_test() {
    ProxyConfig *f = ProxyConfig::get_proxy_config("fastly");

    auto s = TestMutator::get_stream1();
    auto s1 = new H2Stream();
    for (auto frm : *s) {
        if (Frame::has_headers(frm)) {
            auto h = dynamic_cast<Headers*>(frm);
            for (int i = 0; i < h->hdr_pairs.size(); ++i) {
                h->prefixes[i] = PrefType::LITERAL_HEADER_NEVER_INDEXED;
                h->idx_types[i] = IdxType::NONE;
            }
            s1->push_back(frm);
        }
    }
    size_t maxsz = 2048*2;
    char buf[maxsz];
    uint32_t sz = s1->serialize(buf, maxsz);

    for (int i = 0; i < 100000; ++i) {
        std::cout << "-------------- " << i << " --------------" << std::endl;

        H2Mutator m(buf, sz, "/Users/gavazzi.a/CLionProjects/h2_fuzzer/h2_fuzz/mut_config_data.conf");
        Random r_loc(i);
        r = &r_loc;
        m.Mutate(llvm_mutate, i, maxsz/2);

        sz = m.strm_->serialize(buf, maxsz);
        assert(sz <= maxsz);

        char *newdata;
        preprocess_req(*f, (uint8_t*)buf, sz, &newdata);
        delete[] newdata;
    }

    TestMutator::delete_stream(s1);
}

void get_filt(const char *proxy) {
    ProxyConfig::get_proxy_config(proxy);
}

#define LAUNCH(tname, proxy) std::thread tname(get_filt, proxy);
#define CLEAN(tname) tname.join();

void filter_stres_test() {
    for (int i = 0; i < 10000; ++i) {
        LAUNCH(t_nginx, "nginx")
        LAUNCH(t_caddy, "caddy")
        LAUNCH(t_apache, "apache")
        LAUNCH(t_envoy, "envoy")
        LAUNCH(t_haproxy, "haproxy")
        LAUNCH(t_traefik, "traefik")
        LAUNCH(t_varnish, "varnish")
        LAUNCH(t_h2o, "h2o")
        LAUNCH(t_ats, "ats")
        LAUNCH(t_akamai, "akamai")
        LAUNCH(t_cloudflare, "cloudflare")
        LAUNCH(t_cloudfront, "cloudfront")
        LAUNCH(t_fastly, "fastly")

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
    }

    ProxyConfig::clear_cache();
}

#define LAUNCH_HOST(tname, proxy, host, n) std::thread tname(gethost, host);

#include <netdb.h>
void gethost(const char *host) {
    struct hostent *hp = gethostbyname(host);

    if (hp == nullptr) {
        std::cout << "obtained null from gethostbyname" << std::endl;
        return;
    }

    struct sockaddr_in addr{};
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
}

void gethost_stress_test() {
    for (int i = 0; i < 100000; ++i) {
        std::cout << i << std::endl;
        LAUNCH_HOST(t_nginx, "nginx", "172.17.0.2", 0)
        LAUNCH_HOST(t_caddy, "caddy", "172.17.0.3", 1)
        LAUNCH_HOST(t_apache, "apache", "172.17.0.9", 2)
        LAUNCH_HOST(t_envoy, "envoy", "172.17.0.10", 3)
        LAUNCH_HOST(t_haproxy, "haproxy", "172.17.0.11", 4)
        LAUNCH_HOST(t_traefik, "traefik", "172.17.0.12", 5)
        LAUNCH_HOST(t_varnish, "varnish", "172.17.0.13", 6)
        LAUNCH_HOST(t_h2o, "h2o", "172.17.0.14", 7)
        LAUNCH_HOST(t_ats, "ats", "172.17.0.15", 8)
        LAUNCH_HOST(t_akamai, "akamai", "172.17.0.5", 9)
        LAUNCH_HOST(t_cloudflare, "cloudflare", "172.17.0.6", 10)
        LAUNCH_HOST(t_cloudfront, "cloudfront", "172.17.0.7", 11)
        LAUNCH_HOST(t_fastly, "fastly", "172.17.0.8", 12)

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
    }
}

int main() {
    gethost_stress_test();
}
