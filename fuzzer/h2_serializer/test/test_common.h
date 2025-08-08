#ifndef H2SRLZ_TEST_COMMON_H
#define H2SRLZ_TEST_COMMON_H

#include "../src/frames/frames.h"
#include "../src/frames/common/membuf.h"
#include "../src/frame_copier.h"

#define DYN_TAB_UPDATE "\x3f\xe1\x1f"

void test_srlz_common(Frame* f, const char* answer, uint32_t bufsz, bool print=false);

void test_desrlz_common(char* in, uint32_t insz, Frame* answer);

void frame_eq(Frame *out, Frame *answer);


#endif
