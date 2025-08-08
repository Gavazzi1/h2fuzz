
#include <string>
#include <sstream>

#include "h2mutator.h"

#define CFG "/fuzzer/h2_fuzz/mut_config_data.conf"

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
    std::string s(reinterpret_cast<const char*>(Data), Size);
    std::stringstream in(s);
    std::stringstream out;
    H2Mutator h2m(in, CFG);
    if (!h2m.Mutate(LLVMFuzzerMutate, Seed, MaxSize)) {
        return 0;
    }

    if (h2m.strm_ == nullptr) {
        return Size;
    }

    // TODO make serialize take in a stream to i don't have to worry about memory management
    char buf[MaxSize];
    uint32_t newsz = h2m.strm_->serialize(buf, MaxSize);
    if (newsz > MaxSize) {
        return 0;
    }
    memcpy(Data, buf, newsz);
    return newsz;
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                            const uint8_t *Data2, size_t Size2,
                                            uint8_t *Out, size_t MaxSize,
                                            unsigned int Seed) {
    std::stringstream in1(std::string(reinterpret_cast<const char *>(Data1), Size1));
    std::stringstream in2(std::string(reinterpret_cast<const char *>(Data2), Size2));
    H2Mutator h2m1(in1, CFG);
    H2Mutator h2m2(in2, CFG);
    if (!h2m1.CrossOver(h2m2, Seed, MaxSize)) {
        return 0;
    }

    // if parsing streams fails for some reason
    if (h2m1.strm_ == nullptr) {
        memcpy(Out, Data1, Size1);
        return 0;
    }

    uint32_t newsz = h2m1.strm_->serialize((char*)Out, MaxSize);
    if (newsz > MaxSize) {
        return 0;
    }
    return newsz;
}
