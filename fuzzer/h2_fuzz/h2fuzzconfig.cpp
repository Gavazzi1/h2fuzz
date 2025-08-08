
#include "h2fuzzconfig.h"

const std::map<std::string, uint8_t> H2FuzzConfig::str2frametype_ = {
        {"base", BASE},
        {"depweight", DEPWEIGHT},
        {"header", HDRS},
        {"pad", PAD},
        {"data", DATA},
        {"rst_stream", RST_STREAM},
        {"settings", SETTINGS},
        {"push_prom", PUSH_PROMISE},
        {"ping", PING},
        {"goaway", GOAWAY},
        {"win_update", WINDOW_UPDATE},
        {"headers", HEADERS}
};

const std::map<std::string, FrameField> H2FuzzConfig::str2frmfld_ = {
        {"length", FrameField::Length},
        {"type", FrameField::Type},
        {"flags", FrameField::Flags},
        {"reserved", FrameField::Reserved},
        {"streamid", FrameField::StreamID},
        {"padding", FrameField::Padding},
        {"padflag", FrameField::PadFlag},
        {"data", FrameField::Data},
        {"exclusive", FrameField::Exclusive},
        {"weight", FrameField::Weight},
        {"priorityflag", FrameField::PriorityFlag},
        {"name", FrameField::Name},
        {"value", FrameField::Value},
        {"encoding", FrameField::Encoding},
        {"errcode", FrameField::ErrCode},
        {"id", FrameField::ID},
        {"increment", FrameField::Increment},
        {"dup", FrameField::Dup},
        {"delete", FrameField::Delete},
        {"swap", FrameField::Swap},
        {"split", FrameField::Split}
};