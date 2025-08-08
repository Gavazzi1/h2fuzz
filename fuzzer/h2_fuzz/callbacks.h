#ifndef NEZHA_CALLBACKS_H
#define NEZHA_CALLBACKS_H

#include <cstdint>
#include <cstdlib>
#include "proxy_config.h"
#include "hashcomp.h"
#include "../h2_serializer/src/frames/h2stream.h"

typedef HashComp* CallbackRet;

void del_stream(H2Stream *strm);

size_t preprocess_req(const ProxyConfig &filt, const uint8_t *Data, size_t Size, char **new_data);

HashComp *callback_test(const char *proxy, int reqid, const ProxyConfig &filt);

HashComp *callback(const char *addr, int port, const ProxyConfig &filt, const uint8_t *Data, size_t Size);


#endif
