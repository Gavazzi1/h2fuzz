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

#include "HPackTable.h"

using namespace hpack;

#include "StaticTable.h"

HPackTable::HPackTable() {
    for (int i = 0; i < HPACK_STATIC_TABLE_SIZE; ++i) {
        std::pair<std::string, std::string> key_nv(hpackStaticTable[i].first, hpackStaticTable[i].second);
        indexMapNV_.emplace(std::move(key_nv), std::make_pair(-1, i));

        std::string key_n = hpackStaticTable[i].first;
        indexMapN_.emplace(std::move(key_n), std::make_pair(-1, i));
    }
}

bool HPackTable::getIndexedName(int index, std::string &name) {
    if (index <= 0) {
        return false;
    }
    if (index < HPACK_DYNAMIC_START_INDEX) {
        name = hpackStaticTable[index - 1].first;
    } else if (index - HPACK_DYNAMIC_START_INDEX < static_cast<int>(dynamicTable_.size())) {
        name = dynamicTable_[index - HPACK_DYNAMIC_START_INDEX].first;
    } else {
        return false;
    }
    return true;
}

bool HPackTable::getIndexedValue(int index, std::string &value)
{
    if (index <= 0) {
        return false;
    }
    if (index < HPACK_DYNAMIC_START_INDEX) {
        value = hpackStaticTable[index - 1].second;
    } else if (index - HPACK_DYNAMIC_START_INDEX < static_cast<int>(dynamicTable_.size())) {
        value = dynamicTable_[index - HPACK_DYNAMIC_START_INDEX].second;
    } else {
        return false;
    }
    return true;
}

bool HPackTable::addHeader(const std::string &name, const std::string &value)
{
    uint32_t entrySize = uint32_t(name.length() + value.length() + TABLE_ENTRY_SIZE_EXTRA);
    if (entrySize + tableSize_ > limitSize_) {
        evictTableBySize(entrySize + tableSize_ - limitSize_);
    }
    if (entrySize > limitSize_) {
        return false;
    }
    dynamicTable_.push_front(std::make_pair(name, value));
    tableSize_ += entrySize;
    if (isEncoder_) {
        updateIndex(name, value, ++indexSequence_);
    }
    return true;
}

void HPackTable::setMaxSize(size_t maxSize)
{
    maxSize_ = maxSize;
    if (limitSize_ > maxSize_) {
        updateLimitSize(maxSize_);
    }
}

void HPackTable::updateLimitSize(size_t limitSize)
{
    if (tableSize_ > limitSize) {
        evictTableBySize(tableSize_ - limitSize);
    }
    limitSize_ = limitSize;
}

void HPackTable::evictTableBySize(size_t size)
{
    uint32_t evicted = 0;
    while (evicted < size && !dynamicTable_.empty()) {
        auto &entry = dynamicTable_.back();
        uint32_t entrySize = uint32_t(entry.first.length() + entry.second.length() + TABLE_ENTRY_SIZE_EXTRA);
        tableSize_ -= tableSize_ > entrySize ? entrySize : tableSize_;
        if (isEncoder_) {
            removeIndex(entry.first, entry.second);
        }
        dynamicTable_.pop_back();
        evicted += entrySize;
    }
}

int HPackTable::getDynamicIndex(int idxSeq)
{
    return -1 == idxSeq ? -1 : indexSequence_ - idxSeq;
}

void HPackTable::updateIndex(const std::string &name, const std::string &value, int idxSeq)
{
    // update index for <name, value> pair
    std::pair<std::string, std::string> key(name, value);
    auto it_nv = indexMapNV_.find(key);
    if (it_nv != indexMapNV_.end()) {
        it_nv->second.first = idxSeq;
    } else {
        indexMapNV_.emplace(key, std::make_pair(idxSeq, -1));
    }

    // update index for name only
    auto it_n = indexMapN_.find(name);
    if (it_n != indexMapN_.end()) {
        it_n->second.first = idxSeq;
    } else {
        indexMapN_.emplace(name, std::make_pair(idxSeq, -1));
    }
}

void HPackTable::removeIndex(const std::string &name, const std::string &value)
{
    std::pair<std::string, std::string> key(name, value);
    auto it = indexMapNV_.find(key);
    if (it != indexMapNV_.end()) {                          // if we find the name/value pair
        int idx = getDynamicIndex(it->second.first); // get its index in the dynamic table
        if (idx == dynamicTable_.size() - 1) {              // if it is the last element in the dynamic table
            if (it->second.second == -1) {                  // and it is NOT in the static table
                indexMapNV_.erase(it);                   // remove it from the index map entirely
            } else {                                        // otherwise
                it->second.first = -1;                      // reset dynamic table index without removal
            }
        }
    }

    auto it_n = indexMapN_.find(name);
    if (it_n != indexMapN_.end()) {
        int idx = getDynamicIndex(it_n->second.first);
        if (idx == dynamicTable_.size() - 1) {
            if (it_n->second.second == -1) {
                indexMapN_.erase(it_n);
            } else {
                it_n->second.first = -1;
            }
        }
    }
}

bool HPackTable::getIndexNV(const std::pair<std::string, std::string> &key, int &indexD, int &indexS)
{
    indexD = -1;
    indexS = -1;
    auto it = indexMapNV_.find(key);
    if (it != indexMapNV_.end()) {
        indexD = getDynamicIndex(it->second.first);
        indexS = it->second.second;
        return true;
    }
    return false;
}

bool HPackTable::getIndexN(const std::string &key, int &indexD, int &indexS)
{
    indexD = -1;
    indexS = -1;
    auto it = indexMapN_.find(key);
    if (it != indexMapN_.end()) {
        indexD = getDynamicIndex(it->second.first);
        indexS = it->second.second;
        return true;
    }
    return false;
}

int HPackTable::getIndex(const std::string &name, const std::string &value, bool &valueIndexed)
{
    int index = -1, indexD = -1, indexS = -1;
    valueIndexed = false;

    std::pair<std::string, std::string> key(name, value);
    if (!getIndexNV(key, indexD, indexS)) {
        getIndexN(name, indexD, indexS);
    }
    if (indexD != -1 && indexD < static_cast<int>(dynamicTable_.size()) && name == dynamicTable_[indexD].first) {
        index = indexD + HPACK_DYNAMIC_START_INDEX;
        valueIndexed = dynamicTable_[indexD].second == value;
    } else if (indexS != -1 && indexS < HPACK_STATIC_TABLE_SIZE && name == hpackStaticTable[indexS].first) {
        index = indexS + 1;
        valueIndexed = hpackStaticTable[indexS].second == value;
    }
    return index;
}
