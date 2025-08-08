#ifndef H2SRLZ_SETTINGSFRAME_H
#define H2SRLZ_SETTINGSFRAME_H

#include <vector>
#include "common/baseframe.h"
#include "common/utils.h"

typedef std::pair<uint16_t, uint32_t> Setting;

#define SETTINGS_HEADER_TABLE_SIZE 0x1
#define SETTINGS_ENABLE_PUSH 0x2
#define SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define SETTINGS_INITIAL_WINDOW_SIZE 0x4
#define SETTINGS_MAX_FRAME_SIZE 0x5
#define SETTINGS_MAX_HEADER_LIST_SIZE 0x6

/*
    +-------------------------------+
    |       Identifier (16)         |
    +-------------------------------+-------------------------------+
    |                        Value (32)                             |
    +---------------------------------------------------------------+
 */
class SettingsFrame : public Frame {
public:
    SettingsFrame() {
        this->type = SETTINGS;
    }

    virtual ~SettingsFrame() {}

    void add_setting(uint16_t id, uint32_t value) {
        Setting s(id, value);
        this->settings.push_back(s);
    }

    uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe, bool pres_flags) override {
        this->payload_ = new char[6 * this->settings.size()];
        uint32_t pos = 0;

        for (Setting s : this->settings) {
            char id_buf[2];
            Utils::uint16_to_buf(id_buf, s.first);
            memcpy(this->payload_ + pos, id_buf, 2);
            pos += 2;

            char val_buf[4];
            Utils::uint32_to_buf(val_buf, s.second);
            memcpy(this->payload_ + pos, val_buf, 4);
            pos += 4;
        }

        this->len = pos;

        // serialize the entire dataframe
        return serialize_common_(buf, sz);
    }

    std::vector<Setting> settings;
};

#endif
