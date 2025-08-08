#pragma once

#include <iostream>

#define DBG_MODE 0

#if DBG_MODE == 1
#define DEBUG(x) std::cerr << x << std::endl;
#define DEBUG_NOLN(x) std::cerr << x;
#else
#define DEBUG(x)
#define DEBUG_NOLN(x)
#endif
