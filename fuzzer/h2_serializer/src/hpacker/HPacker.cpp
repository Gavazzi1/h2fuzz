/* Copyright (c) 2016, Fengping Bao <jamol@live.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "HPacker.h"
#include "hpack_huffman_table.h"

#include <math.h>
#include <string.h> // for memcpy

namespace hpack {

static char *huffDecodeBits(char *dst, uint8_t bits, uint8_t *state, bool *ending) {
    const auto &entry = huff_decode_table[*state][bits];
    
    if ((entry.flags & NGHTTP2_HUFF_FAIL) != 0)
        return nullptr;
    if ((entry.flags & NGHTTP2_HUFF_SYM) != 0)
        *dst++ = entry.sym;
    *state = entry.state;
    *ending = (entry.flags & NGHTTP2_HUFF_ACCEPTED) != 0;
    
    return dst;
}

static int huffDecode(const uint8_t *src, size_t len, std::string &str) {
    uint8_t state = 0;
    bool ending = false;
    const uint8_t *src_end = src + len;

    std::vector<char> sbuf;
    sbuf.resize(2*len);
    char *ptr = &sbuf[0];
    
    for (; src != src_end; ++src) {
        if ((ptr = huffDecodeBits(ptr, *src >> 4, &state, &ending)) == nullptr)
            return -1;
        if ((ptr = huffDecodeBits(ptr, *src & 0xf, &state, &ending)) == nullptr)
            return -1;
    }
    if (!ending) {
        return -1;
    }
    int slen = int(ptr - &sbuf[0]);
    str.assign(&sbuf[0], slen);
    return slen;
}

static int huffEncode(const std::string &str, uint8_t *buf, size_t len) {
    uint8_t *ptr = buf;
    //const uint8_t *end = buf + len;
    const char* src = str.c_str();
    const char* src_end = src + str.length();
    
    uint64_t current = 0;
    uint32_t n = 0;
    
    for (; src != src_end;) {
        const auto &sym = huff_sym_table[*src++];
        uint32_t code = sym.code;
        uint32_t nbits = sym.nbits;
        
        current <<= nbits;
        current |= code;
        n += nbits;
        
        while (n >= 8) {
            n -= 8;
            *ptr++ = static_cast<uint8_t>(current >> n);
        }
    }
    
    if (n > 0) {
        current <<= (8 - n);
        current |= (0xFF >> n);
        *ptr++ = static_cast<uint8_t>(current);
    }
    
    return int(ptr - buf);
}

static uint32_t huffEncodeLength(const std::string &str)
{
    uint32_t len = 0;
    for (unsigned char c : str) {
        len += huff_sym_table[c].nbits;
    }
    return (len + 7) >> 3;
}

static int encodeInteger(uint8_t N, uint64_t I, uint8_t *buf, size_t len) {
    uint8_t *ptr = buf;
    const uint8_t *end = buf + len;
    if (ptr == end) {
        return -1;
    }
    uint8_t NF = (1 << N) - 1;
    if (I < NF) {
        *ptr &= NF ^ 0xFF;
        *ptr |= I;
        return 1;
    }
    *ptr++ |= NF;
    I -= NF;
    while (ptr < end && I >= 128) {
        *ptr++ = I % 128 + 128;
        I /= 128;
    }
    if (ptr == end) {
        return -1;
    }
    *ptr++ = static_cast<uint8_t>(I);
    
    return int(ptr - buf);
}

static int encodeString(const std::string &str, uint8_t *buf, size_t len) {
    // TODO can we huffman encoding work? also, can we enable mutating whether huffman encoding is done?

    uint8_t *ptr = buf;
    uint8_t *end = buf + len;
    
    int slen = int(str.length());
    int hlen = 0;//huffEncodeLength(str);
    if (false) {
        *ptr = 0x80;
        int ret = encodeInteger(7, hlen, ptr, end - ptr);
        if (ret <= 0) {
            return -1;
        }
        ptr += ret;
        ret = huffEncode(str, ptr, end - ptr);
        if (ret < 0) {
            return -1;
        }
        ptr += ret;
    } else {
        *ptr = 0;
        int ret = encodeInteger(7, slen, ptr, end - ptr);
        if (ret <= 0) {
            return -1;
        }
        ptr += ret;
        if (static_cast<size_t>(end - ptr) < str.length()) {
            return -1;
        }
        memcpy(ptr, str.c_str(), str.length());
        ptr += str.length();
    }
    
    return int(ptr - buf);
}

static int decodeInteger(uint8_t N, const uint8_t *buf, size_t len, uint64_t &I) {
    if (N > 8) {
        return -1;
    }
    const uint8_t *ptr = buf;
    const uint8_t *end = buf + len;
    if (ptr == end) {
        return -1;
    }
    uint8_t NF = (1 << N) - 1;
    uint8_t prefix = (*ptr++) & NF;
    if (prefix < NF) {
        I = prefix;
        return 1;
    }
    if (ptr == end) {
        return -1;
    }
    int m = 0;
    uint64_t u64 = prefix;
    uint8_t b = 0;
    do {
        b = *ptr++;
        u64 += static_cast<uint64_t>((b & 127) * pow(2, m));
        m += 7;
    } while (ptr < end && (b & 128));
    if (ptr == end && (b & 128)) {
        return -1;
    }
    I = u64;
    
    return int(ptr - buf);
}

static int decodeString(const uint8_t *buf, size_t len, std::string &str)
{
    const uint8_t *ptr = buf;
    const uint8_t *end = buf + len;
    if (ptr == end) {
        std::cerr << "Error trying to decode string at end of buffer" << std::endl;
        return -1;
    }
    bool H = !!(*ptr & 0x80);
    uint64_t slen = 0;
    int ret = decodeInteger(7, ptr, end - ptr, slen);
    if (ret <= 0) {
        std::cerr << "Error decoding string literal length" << std::endl;
        return -1;
    }
    ptr += ret;
    if (slen > static_cast<size_t>(end - ptr)) {
        std::cerr << "Error: string literal length exceeds bounds of buffer" << std::endl;
        return -1;
    }
    if (H) {
        if(huffDecode(ptr, static_cast<size_t>(slen), str) < 0) {
            return -1;
        }
    } else {
        str.assign((const char*)ptr, static_cast<size_t>(slen));
    }
    ptr += slen;
    
    return int(ptr - buf);
}

static int decodePrefix(const uint8_t *buf, size_t len, HPacker::PrefixType &type, uint64_t &I) {
    const uint8_t *ptr = buf;
    const uint8_t *end = buf + len;
    uint8_t N = 0;
    if (*ptr & 0x80) {
        N = 7;
        type = HPacker::PrefixType::INDEXED_HEADER;
    } else if (*ptr & 0x40) {
        N = 6;
        type = HPacker::PrefixType::LITERAL_HEADER_WITH_INDEXING;
    } else if (*ptr & 0x20) {
        N = 5;
        type = HPacker::PrefixType::TABLE_SIZE_UPDATE;
    } else if (*ptr & 0x10) {
        N = 4;
        type = HPacker::PrefixType::LITERAL_HEADER_NEVER_INDEXED;
    } else {
        N = 4;
        type = HPacker::PrefixType::LITERAL_HEADER_WITHOUT_INDEXING;
    }
    int ret = decodeInteger(N, ptr, end - ptr, I);
    if (ret <= 0) {
        return -1;
    }
    ptr += ret;
    return int(ptr - buf);
}

int HPacker::encodeSizeUpdate(int sz, uint8_t *buf, size_t len)
{
    uint8_t *ptr = buf;
    const uint8_t *end = buf + len;
    *ptr = 0x20;
    int ret = encodeInteger(5, sz, ptr, end - ptr);
    if (ret <= 0) {
        return -1;
    }
    ptr += ret;
    return int(ptr - buf);
}

int HPacker::encodeHeader(const std::string &name, const std::string &value, uint8_t *buf, size_t len, PrefixType pref, IndexingType idx_type)
{
    uint8_t *ptr = buf;
    const uint8_t *end = buf + len;
    
    bool valueIndexed = false;
    int index = table_.getIndex(name, value, valueIndexed);
    bool nameIndexed = index != -1;

    // check invariants and throw errors if prefix and index types are invalid
    if (
            (pref == PrefixType::INDEXED_HEADER && idx_type != IndexingType::ALL) ||
            (idx_type == IndexingType::ALL && pref != PrefixType::INDEXED_HEADER) ||
            (pref == PrefixType::INDEXED_HEADER && (!nameIndexed || !valueIndexed)) ||
            (idx_type == IndexingType::NAME && !nameIndexed)) {
        return -1;
    }

    // set prefix value in buffer
    bool addToTable = false;
    uint8_t n_bits;
    switch (pref) {
        case PrefixType::INDEXED_HEADER:
            *ptr = 0x80;
            n_bits = 7;
            break;
        case PrefixType::LITERAL_HEADER_WITH_INDEXING:
            addToTable = true;
            *ptr = 0x40;
            n_bits = 6;
            break;
        case PrefixType::LITERAL_HEADER_WITHOUT_INDEXING:
            *ptr = 0x00;
            n_bits = 4;
            break;
        case PrefixType::LITERAL_HEADER_NEVER_INDEXED:
            *ptr = 0x10;
            n_bits = 4;
            break;
        default:
            return -1;
    }

    if (idx_type == IndexingType::NONE) {
        // nothing indexed
        // skip encoding index
        ++ptr;

        // encode name
        int ret = encodeString(name, ptr, end - ptr);
        if (ret <= 0) {
            return -1;
        }
        ptr += ret;
    } else {
        // encode index in table
        int ret = encodeInteger(n_bits, index, ptr, end - ptr);
        if (ret <= 0) {
            return -1;
        }
        ptr += ret;
    }

    // encode value as long as this isn't fully indexed
    if (idx_type != IndexingType::ALL) {
        int ret = encodeString(value, ptr, end - ptr);
        if (ret <= 0) {
            return -1;
        }
        ptr += ret;
    }

    if (addToTable) {
        table_.addHeader(name, value);
    }
    return int(ptr - buf);
}

int HPacker::encode(const KeyValueVector &headers, uint8_t *buf, size_t len, std::vector<PrefixType> &prefixes, std::vector<IndexingType> &idx_types) {
    table_.setMode(true);
    uint8_t *ptr = buf;
    const uint8_t *end = buf + len;

    // require that the prefixes and indexing types be specified for each header
    if (headers.size() != prefixes.size() || headers.size() != idx_types.size()) {
        std::cerr << "Mismatch in number of headers and number of prefix/index types" << std::endl;
        return -1;
    }
    
    if (updateTableSize_) {
        updateTableSize_ = false;
        int ret = encodeSizeUpdate(int(table_.getLimitSize()), ptr, end - ptr);
        if (ret <= 0) {
            std::cerr << "Error in encoding size update" << std::endl;
            return -1;
        }
        ptr += ret;
    }
    for (int i = 0; i < headers.size(); ++i) {
        const auto &hdr = headers[i];

        int ret = encodeHeader(hdr.first, hdr.second, ptr, end - ptr, prefixes[i], idx_types[i]);
        if (ret <= 0) {
            std::cerr << "Error in encoding header at index " << i << std::endl;
            return -1;
        }
        ptr += ret;
    }
    return int(ptr - buf);
}

int HPacker::decode(const uint8_t *buf, size_t len, KeyValueVector &headers, std::vector<PrefixType> &prefixes, std::vector<IndexingType> &idx_types) {
    table_.setMode(false);
    const uint8_t *ptr = buf;
    const uint8_t *end = buf + len;
    headers.clear();
    prefixes.clear();
    idx_types.clear();
    
    while (ptr < end) {
        std::string name;
        std::string value;
        PrefixType pref_type;
        IndexingType idx_type;
        uint64_t I = 0;
        int ret = decodePrefix(ptr, end - ptr, pref_type, I);
        if (ret <= 0) {
            std::cerr << "Error decoding prefix" << std::endl;
            return -1;
        }
        ptr += ret;
        if (PrefixType::INDEXED_HEADER == pref_type) {
            idx_type = IndexingType::ALL;  // INVARIANT: if Pref==INDEXED_HEADER, then Idx==ALL
            if (!table_.getIndexedName(int(I), name) || !table_.getIndexedValue(int(I), value)) {
                std::cerr << "Error finding entire header at index " << I << " in HPACK table" << std::endl;
                return -1;
            }
        } else if (PrefixType::LITERAL_HEADER_WITH_INDEXING == pref_type ||
                   PrefixType::LITERAL_HEADER_WITHOUT_INDEXING == pref_type ||
                   PrefixType::LITERAL_HEADER_NEVER_INDEXED == pref_type) {
            idx_type = IndexingType::NAME;
            if (0 == I) {
                idx_type = IndexingType::NONE;
                ret = decodeString(ptr, end - ptr, name);
                if (ret <= 0) {
                    std::cerr << "Error decoding name literal" << std::endl;
                    return -1;
                }
                ptr += ret;
            } else if (!table_.getIndexedName(int(I), name)) {
                std::cerr << "Error getting header name at index " << I << " in HPACK table" << std::endl;
                return -1;
            }
            ret = decodeString(ptr, end - ptr, value);
            if (ret <= 0) {
                std::cerr << "Error decoding value literal" << std::endl;
                return -1;
            }
            ptr += ret;
            if (PrefixType::LITERAL_HEADER_WITH_INDEXING == pref_type) {
                table_.addHeader(name, value);
            }
        } else if (PrefixType::TABLE_SIZE_UPDATE == pref_type) {
            if (I > table_.getMaxSize()) {
                std::cerr << "Error decoding table size update. I=" << I << ", MaxSize=" << table_.getMaxSize() << std::endl;
                return -1;
            }
            table_.updateLimitSize(static_cast<size_t>(I));
            continue;
        }

        headers.emplace_back(std::make_pair(name, value));
        prefixes.emplace_back(pref_type);
        idx_types.emplace_back(idx_type);
    }
    return int(len);
}

} // namespace hpack
