#ifndef NEZHA_UTILS_H
#define NEZHA_UTILS_H

#include <vector>
#include <string>


class HashUtils {
public:
    static size_t checksum(std::string *str) {
        if (str == nullptr) {
            return 0;
        }

        size_t out = 0;
        for (char c : *str) {
            out += c;
        }
        return out;
    }

    static size_t checksum(const std::vector<std::string> &vec) {
        size_t out = 0;
        for (auto s : vec) {
            out += HashUtils::checksum(&s);
        }
        return out;
    }

    static bool cmp_str(std::string *s1, std::string *s2) {
        return *s1 < *s2;
    }
};


#endif
