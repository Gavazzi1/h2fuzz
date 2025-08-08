
#include "proxy_config.h"

std::map<std::string, ProxyConfig*> ProxyConfig::cache;
std::mutex ProxyConfig::proxy_config_mtx;