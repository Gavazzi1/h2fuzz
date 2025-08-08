#ifndef H2SRLZ_DESERIALIZER_H
#define H2SRLZ_DESERIALIZER_H

#include "frames/h2stream.h"
#include "frames/frames.h"
#include "hpacker/HPacker.h"
#include "frames/common/membuf.h"

struct FrameHdr {
    uint32_t len;
    uint8_t type;
    uint8_t flags;
    bool reserved;
    uint32_t sid;
};

typedef std::pair<bool, uint32_t> BitUint32;

class Deserializer {
public:
    static H2Stream* deserialize_stream(std::istream &in) {
        hpack::HPacker hpe;  // shared HPACK context for entire stream
        auto *out = new H2Stream();

        // probably a smarter way to do this, but it's all I got
        in.peek();
        while (!in.eof()) {
            out->push_back(deserialize_frame(in, &hpe));
            in.peek();
        }

        return out;
    }

    static H2Stream* deserialize_stream(const char *buf, size_t sz) {
        // const cast because I promise deserialize_stream doesn't mess with the data
        membuf sbuf(const_cast<char*>(buf), const_cast<char*>(buf) + sz);
        std::istream in(&sbuf);
        return Deserializer::deserialize_stream(in);
    }

    /**
     * Deserializes a single frame (of any type) from given istream, which contains a serialized representation of
     * the frame
     */
    static Frame* deserialize_frame(std::istream &in, hpack::HPacker *hpe) {
        FrameHdr hdr{};
        char lenbuf[] = "\0\0\0\0";
        read_with_error(in, lenbuf + 1, 3);
        hdr.len = Utils::buf_to_uint32(lenbuf);
        read_with_error(in, (char *) &hdr.type, 1);
        read_with_error(in, (char *) &hdr.flags, 1);

        BitUint32 bu32 = desrlz_bit_uint32(in);
        hdr.reserved = bu32.first;
        hdr.sid = bu32.second;

        switch (hdr.type) {
            case DATA:
                return desrlz_dataframe(hdr,in);
            case HEADERS:
                return desrlz_headersframe(hdr, in, hpe);
            case PRIORITY_TYPE:
                return desrlz_priorityframe(hdr, in);
            case RST_STREAM:
                return desrlz_rst_streamframe(hdr, in);
            case SETTINGS:
                return desrlz_settingsframe(hdr, in);
            case PUSH_PROMISE:
                return desrlz_push_promiseframe(hdr, in, hpe);
            case PING:
                return desrlz_pingframe(hdr, in);
            case GOAWAY:
                return desrlz_goaway(hdr, in);
            case WINDOW_UPDATE:
                return desrlz_window_updateframe(hdr, in);
            case CONTINUATION:
                return desrlz_continuation(hdr, in, hpe);
            default:
                throw std::invalid_argument("Deserializer: Unknown frame type");
        }
    }

private:
    /**
     * Reads "sz" bytes from the istream "in" into the buffer "buf," throwing a std::ios_base failure if the number of
     * bytes read does not equal "sz"
     */
    static void read_with_error(std::istream &in, char* buf, uint32_t sz) {
        in.read(buf, sz);
        uint32_t prevrd = in.gcount();
        if (prevrd != sz) {
            std::string errmsg = "Incorrect number of bytes read from istream. Expected " + std::to_string(sz) + " and got " + std::to_string(prevrd);
            throw std::ios_base::failure(errmsg);
        }
    }

    static void desrlz_common(const FrameHdr &hdr, Frame *out) {
        out->len = hdr.len;
        out->flags = hdr.flags;
        out->reserved = hdr.reserved;
        out->stream_id = hdr.sid;
    }

    static BitUint32 desrlz_bit_uint32(std::istream &in) {
        char buf[4];
        read_with_error(in, buf, 4);
        uint32_t val = Utils::buf_to_uint32(buf);
        bool bit = val & 0x80000000;
        val &= 0x7fffffff;
        return BitUint32(bit, val);
    }

    static void desrlz_padlen(const FrameHdr &hdr, Padded* out, std::istream &in) {
        // padding fields
        if (hdr.flags & FLAG_PADDED) {
            read_with_error(in, (char *) &out->padlen, 1);
        } else {
            out->padlen = 0;
        }
    }

    /**
     * Deserializes a DataFrame payload from the istream at its current position.
     */
    static DataFrame* desrlz_dataframe(const FrameHdr &hdr, std::istream &in) {
        auto* out = new DataFrame();
        desrlz_common(hdr, out);

        // padding fields
        desrlz_padlen(hdr, out, in);
        uint32_t remlen = out->len;
        if (hdr.flags & FLAG_PADDED) {
            remlen = remlen - 1 - out->padlen;
        }

        char buf[remlen+1];
        read_with_error(in, buf, remlen);
        out->data.insert(out->data.end(), buf, buf + remlen);

        // read padding into dummy buffer
        desrlz_padding(out, in, hdr);

        return out;
    }

    /**
     * Deserializes the exclusive bit, stream dependency, and weight.
     */
    static void desrlz_depweight(DepWeight *out, std::istream &in) {
        BitUint32 bu32 = desrlz_bit_uint32(in);
        out->exclusive = bu32.first;
        out->stream_dep = bu32.second;
        read_with_error(in, (char*) &out->weight, 1);
    }

    /**
     * Deserializes the raw header fields from a buffer
     */
    static void desrlz_headers(Headers* out, std::istream &in, uint32_t sz, hpack::HPacker *hpe) {
        uint8_t hdr_buf[sz+1];
        read_with_error(in, (char*) hdr_buf, sz);

        int ret = hpe->decode(hdr_buf, sz, out->hdr_pairs, out->prefixes, out->idx_types);
        if (ret == -1) {
            throw std::runtime_error("Error in decoding HPACK body");
        }
        out->hdr_blk_sz = ret;
    }

    /**
     * Deserializes padding from a given buffer
     */
    static void desrlz_padding(Padded *out, std::istream &in, const FrameHdr &hdr) {
        // read padding into padding vector
        char padbuf[out->padlen+1];
        if (hdr.flags & FLAG_PADDED) {
            read_with_error(in, padbuf, out->padlen);
        }
        out->padding.insert(out->padding.end(), padbuf, padbuf+out->padlen);
    }

    /**
     * Deserializes a HeadersFrame payload from the istream at its current position.
     */
    static HeadersFrame* desrlz_headersframe(const FrameHdr &hdr, std::istream &in, hpack::HPacker *hpe) {
        auto *out = new HeadersFrame();
        desrlz_common(hdr, out);

        // padding fields
        desrlz_padlen(hdr, out, in);
        uint32_t remlen = out->len;
        if (hdr.flags & FLAG_PADDED) {
            remlen = remlen - 1 - out->padlen;
        }

        // exclusive bit, stream dependency, and weight fields
        if (hdr.flags & FLAG_PRIORITY) {
            desrlz_depweight(out, in);
            remlen -= 5;  // 4 for exclusive + stream dep, 1 for weight
        }

        // header block
        desrlz_headers(out, in, remlen, hpe);

        // read padding into dummy buffer
        desrlz_padding(out, in, hdr);

        return out;
    }

    /**
     * Deserializes a PriorityFrame payload from the istream at its current position.
     */
    static PriorityFrame* desrlz_priorityframe(const FrameHdr &hdr, std::istream &in) {
        auto *out = new PriorityFrame();
        desrlz_common(hdr, out);
        desrlz_depweight(out, in);
        return out;
    }

    /**
     * Deserializes a RstStreamFrame payload from the istream at its current position.
     */
    static RstStreamFrame* desrlz_rst_streamframe(const FrameHdr &hdr, std::istream &in) {
        auto *out = new RstStreamFrame();
        desrlz_common(hdr, out);
        char codebuf[4];
        read_with_error(in, codebuf, 4);
        out->error_code = Utils::buf_to_uint32(codebuf);
        return out;
    }

    /**
     * Deserializes a SettingsFrame payload from the istream at its current position.
     */
    static SettingsFrame* desrlz_settingsframe(const FrameHdr &hdr, std::istream &in) {
        auto *out = new SettingsFrame();
        desrlz_common(hdr, out);

        uint32_t nsettings = out->len / 6;
        for (int i = 0; i < nsettings; ++i) {
            Setting s;
            char id_buf[2];
            read_with_error(in, id_buf, 2);
            s.first = Utils::buf_to_uint16(id_buf);

            char val_buf[4];
            read_with_error(in, val_buf, 4);
            s.second = Utils::buf_to_uint32(val_buf);

            out->settings.push_back(s);
        }

        return out;
    }

    /**
     * Deserializes a PushPromiseFrame payload from the istream at its current position.
     */
    static PushPromiseFrame* desrlz_push_promiseframe(const FrameHdr &hdr, std::istream &in, hpack::HPacker *hpe) {
        auto *out = new PushPromiseFrame();
        desrlz_common(hdr, out);

        // padding fields
        desrlz_padlen(hdr, out, in);
        uint32_t remlen = out->len;
        if (hdr.flags & FLAG_PADDED) {
            remlen = remlen - 1 - out->padlen;
        }

        // reserved and promised stream ID
        BitUint32 bu32 = desrlz_bit_uint32(in);
        out->reserved_pp = bu32.first;
        out->prom_stream_id = bu32.second;
        remlen -= 4;

        // headers
        desrlz_headers(out, in, remlen, hpe);

        // padding
        desrlz_padding(out, in, hdr);

        return out;
    }

    /**
     * Deserializes a PingFrame payload from the istream at its current position.
     */
    static PingFrame* desrlz_pingframe(const FrameHdr &hdr, std::istream &in) {
        auto *out = new PingFrame();
        desrlz_common(hdr, out);
        char data_buf[8];
        read_with_error(in, data_buf, 8);
        out->data = Utils::buf_to_uint64(data_buf);
        return out;
    }

    /**
     * Deserializes a GoAway payload from the istream at its current position.
     */
    static GoAway* desrlz_goaway(const FrameHdr &hdr, std::istream &in) {
        auto *out = new GoAway();
        desrlz_common(hdr, out);

        // reserved and last stream id
        BitUint32 bu32 = desrlz_bit_uint32(in);
        out->reserved_ga = bu32.first;
        out->last_stream_id = bu32.second;

        // error code
        char error_buf[4];
        read_with_error(in, error_buf, 4);
        out->error_code = Utils::buf_to_uint32(error_buf);

        // debug data
        size_t remlen = out->len - 8;
        if (remlen > 0) {
            char buf[remlen];
            read_with_error(in, buf, remlen);
            out->debug_data.insert(out->debug_data.end(), buf, buf + remlen);
        }

        return out;
    }

    /**
     * Deserializes a WindowUpdate payload from the istream at its current position.
     */
    static WindowUpdate* desrlz_window_updateframe(const FrameHdr &hdr, std::istream &in) {
        auto *out = new WindowUpdate();
        desrlz_common(hdr, out);

        // reserved and window size update
        BitUint32 bu32 = desrlz_bit_uint32(in);
        out->reserved_wu = bu32.first;
        out->win_sz_inc = bu32.second;

        return out;
    }

    /**
     * Deserializes a Continuation payload from the istream at its current position.
     */
    static Continuation* desrlz_continuation(const FrameHdr &hdr, std::istream &in, hpack::HPacker *hpe) {
        auto *out = new Continuation();
        desrlz_common(hdr, out);
        desrlz_headers(out, in, hdr.len, hpe);
        return out;
    }
};

#endif
