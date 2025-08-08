#ifndef NEZHA_PROXY_CONF_H
#define NEZHA_PROXY_CONF_H

#include <fstream>
#include <set>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <libconfig.h++>
#include "../debug.h"
#include "basedir.h"

#define PROX_CFG_DIR BASEDIR"/proxy_configs"

#define GRAMMAR_AUTH "akamai.test.com"  // defines the default value of the :auth header in the h2gen grammar

/**
 * Per-proxy configuration data.
 */
struct ProxyConfig {
    std::string authority;  // value to set the :authority header in the outgoing request
    std::string host;  // value of host header in the HTTP/1 request
    std::set<std::string> headers;  // headers to exclude from hash and comparisons

    // reduce overhead of reloading configs by implementing a cache
    static std::map<std::string, ProxyConfig*> cache;
    static std::mutex proxy_config_mtx;

    /** Clears the ProxyConfig cache and reclaims all memory */
    static void clear_cache() {
        std::unique_lock<std::mutex> lock(ProxyConfig::proxy_config_mtx);

        for (auto & itr : cache) {
            delete (itr.second);
        }
        cache.clear();
    }

    static ProxyConfig* get_proxy_config(const char *proxy, const char *srcdir) {
        // acquire lock as multiple threads will be requesting configs
        std::unique_lock<std::mutex> lock(ProxyConfig::proxy_config_mtx);

        if (ProxyConfig::cache.count(proxy)) {
            DEBUG("returning proxy config from cache")
            return ProxyConfig::cache[proxy];
        }

        auto *filt = new ProxyConfig();
        libconfig::Config c;

        // get name of file with config contents
        size_t len = strlen(srcdir) + 1 + strlen(proxy) + 1;
        char fn[len];
        snprintf(fn, len, "%s/%s", srcdir, proxy);

        // open and read config
        c.readFile(fn);
        if (!c.exists("filter")) { std::cout << "config does not have \"filter\" element" << std::endl; }

        if (!c.lookupValue("filter.in_host", filt->host)) { std::cout << "config does not have in_host" << std::endl; }
        if (!c.lookupValue("filter.out_authority", filt->authority)) { std::cout << "config does not have out_authority" << std::endl; }

        libconfig::Setting &flt_hdrs = c.lookup("filter.ignore_headers");
        if (!flt_hdrs.isList()) { std::cout << "config ignore_headers is not a list" << std::endl; }
        for (int i = 0; i < flt_hdrs.getLength(); ++i) {
            filt->headers.insert(flt_hdrs[i]);
        }

        ProxyConfig::cache[proxy] = filt;
        DEBUG("loaded proxy config from file system")
        DEBUG_NOLN(filt->host << ", " << filt->authority << ", ")
        for (const auto& hdr : filt->headers) { DEBUG_NOLN(hdr << ", ") }
        DEBUG("")
        return filt;
    }

    /**
     * Reads the configuration for the given proxy into a new ProxyConfig object
     */
    static ProxyConfig* get_proxy_config(const char *proxy) {
        return get_proxy_config(proxy, PROX_CFG_DIR);
    }
};

#endif
