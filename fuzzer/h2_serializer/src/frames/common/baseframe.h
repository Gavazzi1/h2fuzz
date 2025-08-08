#ifndef H2SRLZ_BASEFRAME_H
#define H2SRLZ_BASEFRAME_H

#include <cstring>
#include <cstdint>
#include "utils.h"
#include "../../../../debug.h"
#include "../../hpacker/HPacker.h"

#define MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// General macros
#define HDRSZ 9

// Frame type macros
#define DATA 0x00
#define HEADERS 0x01
#define PRIORITY_TYPE 0x02
#define RST_STREAM 0x03
#define SETTINGS 0x04
#define PUSH_PROMISE 0x05
#define PING 0x06
#define GOAWAY 0x07
#define WINDOW_UPDATE 0x08
#define CONTINUATION 0x09

// Flag macros
#define FLAG_ACK 0x1
#define FLAG_END_STREAM 0x01
#define FLAG_END_HEADERS 0x04
#define FLAG_PADDED 0x08
#define FLAG_PRIORITY 0x20

// Error codes
// "Unknown or unsupported error codes MUST NOT trigger any special behavior.
// These MAY be treated by an implementation as being equivalent to INTERNAL_ERROR."
#define NO_ERROR 0x0
#define PROTOCOL_ERROR 0x1
#define INTERNAL_ERROR 0x2
#define FLOW_CONTROL_ERROR 0x3
#define SETTINGS_TIMEOUT 0x4
#define STREAM_CLOSED 0x5
#define FRAME_SIZE_ERROR 0x6
#define REFUSED_STREAM 0x7
#define CANCEL 0x8
#define COMPRESSION_ERROR 0x9
#define CONNECT_ERROR 0xa
#define ENHANCE_YOUR_CALM 0xb
#define INADEQUATE_SECURITY 0xc
#define HTTP_1_1_REQUIRED 0xd

/**
    +-----------------------------------------------+
    |                 Length (24)                   |
    +---------------+---------------+---------------+
    |   Type (8)    |   Flags (8)   |
    +-+-------------+---------------+-------------------------------+
    |R|                 Stream Identifier (31)                      |
    +=+=============================================================+
    |                   Frame Payload (0...)                      ...
    +---------------------------------------------------------------+
 */
class Frame {
public:
    // set by child classes
    uint32_t len;
    uint8_t type;

    // must be set manually
    uint8_t flags = 0x00;
    uint32_t stream_id = 0x00000000;

    bool reserved  = false; // always 0x0 when sending, but just in case we want to mutate it

    virtual ~Frame() {}

    /*
     * Serializes the given frame and places it in the buffer "buf" of size "sz",
     * returning the size of the serialized data.
     */
    virtual uint32_t serialize(char *buf, uint32_t sz, hpack::HPacker *hpe=nullptr, bool pres_flags=false) = 0;

    /** Returns whether the given frame has headers */
    static bool has_headers(Frame *f) {
        return f->type == CONTINUATION || f->type == HEADERS || f->type == PUSH_PROMISE;
    }

protected:
    // frame payload_ allocated by child class and freed by Frame
    char *payload_ = nullptr;

    /**
     * Serializes the header common to all frames and appends the payload serialized
     * by the child class and stored in this->payload_
     *
     * Returns the size of the entire serialized payload
     */
    uint32_t serialize_common_(char* buf, uint32_t sz, bool pres_flags= false) {
        uint32_t pos = 0;

        // 24-bit length
        char len_buf[4];
        Utils::uint32_to_buf(len_buf, this->len);
        memcpy(buf + pos, &len_buf[1], 3);
        pos += 3;

        // 8-bit frame type
        memcpy(buf + pos++, &this->type, 1);

        // 8-bit flags
        memcpy(buf + pos++, &this->flags, 1);

        // 1-bit reserved and 31-bit stream ID
        uint32_t r_sid = stream_id;
        r_sid |= reserved ? 0x80000000 : 0x00000000;
        Utils::uint32_to_buf(buf + pos, r_sid);
        pos += 4;

        memcpy(buf + pos, this->payload_, this->len);
        delete [] this->payload_; // free buffer allocated in child's serialize()

        return pos + this->len;
    }
};

#endif
