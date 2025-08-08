#include <cstdint>
#include <cstddef>
#include <thread>

#include "callbacks.h"
#include "nezha_diff.h"
#include "normalizer.h"
#include "../debug.h"
#include "../h2_serializer/src/frames/frames.h"

// Generic interface to packages
typedef int (*fp_t)(const uint8_t *, uint32_t);

extern "C" void callback_helper(const char *prox, const char *addr, int port, const uint8_t *Data, size_t Size, HashComp **hc) {
    DEBUG("----- Working on " << prox << " -----")
    ProxyConfig *filt = ProxyConfig::get_proxy_config(prox);
    HashComp *out = callback(addr, port, *filt, Data, Size);
    *hc = out;
}

/** Struct used to initialize global diff-based structures. Static instance ensures that this is called first. */
struct GlobalInitializer {
    GlobalInitializer() {
        // initialize all diff-based structures
        diff_init();
    }
};
static GlobalInitializer g_initializer;

#define PARALLEL 1

#if PARALLEL
#define LAUNCH(tname, fname, addr, idx) std::thread tname(callback_helper, fname, addr, 9090, Data, Size, ret_vals + idx);
#define CLEAN(tname) tname.join();
#else
#define LAUNCH(tname, fname, addr, idx) std::thread tname(callback_helper, fname, addr, 9090, Data, Size, ret_vals + idx); tname.join();
#define CLEAN(tname)
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /**
     * Would be nice to abstract this out -- maybe to the ProxyConfig objects.
     *
     * For now though, it's hard-coded
     */
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

    // check whether any callback returned nullptr (e.g., if client fails to connect)
    bool any_null = false;
    bool all_err = true;
    for (int i = 0; i < total_libs; ++i) {
        if (ret_vals[i] == nullptr) {
            any_null = true;
            break;
        }
        else if (!ret_vals[i]->noresp_err) {
            // flag if at least one input forwards a request and receives a status 200 back
            // this ensure that we don't spend time mutating invalid requests
            all_err = false;
        }
    }

    // clean up HashComps and return error code to Fuzzer::ExecuteCallback
    if (any_null || all_err) {
        for (int i = 0; i < total_libs; ++i) {
            delete ret_vals[i];
        }
        return -1;
    }

    DEBUG("--- Normalizing ---")
    Normalizer::normalize(ret_vals, total_libs);  // perform normalization here. avoids tight coupling inside NEZHA core

#if DBG_MODE
    for (int i=0; i < total_libs; ++i) {
        ret_vals[i]->print_unif();
        DEBUG("")
    }
#endif

    return 0;
}

