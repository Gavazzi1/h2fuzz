#pragma once

#include "frames/frames.h"

class FrameCopier {
public:
    /** Returns a new copy of the given Frame */
    static Frame* copy_frame(Frame *f) {

        switch (f->type) {
            case DATA:
                return copy_dataframe(dynamic_cast<DataFrame*>(f));
            case HEADERS:
                return copy_headersframe(dynamic_cast<HeadersFrame*>(f));
            case PRIORITY_TYPE:
                return copy_priorityframe(dynamic_cast<PriorityFrame*>(f));
            case RST_STREAM:
                return copy_rst_streamframe(dynamic_cast<RstStreamFrame*>(f));
            case SETTINGS:
                return copy_settingsframe(dynamic_cast<SettingsFrame*>(f));
            case PUSH_PROMISE:
                return copy_push_promiseframe(dynamic_cast<PushPromiseFrame*>(f));
            case PING:
                return copy_pingframe(dynamic_cast<PingFrame*>(f));
            case GOAWAY:
                return copy_goaway(dynamic_cast<GoAway*>(f));
            case WINDOW_UPDATE:
                return copy_window_updateframe(dynamic_cast<WindowUpdate*>(f));
            case CONTINUATION:
                return copy_continuation(dynamic_cast<Continuation*>(f));
            default:
                throw std::invalid_argument("FrameCopier: Unknown frame type");
        }
    }

private:
    /** Copies all common Frame fields from "in" to "out" */
    static void copy_baseframe(Frame *in, Frame *out) {
        out->len = in->len;
        out->type = in->type;
        out->flags = in->flags;
        out->stream_id = in->stream_id;
        out->reserved  = in->reserved;
    }

    /** Copies all the common Padded fields from "in" to "out" */
    static void copy_padded(Padded *in, Padded *out) {
        out->padlen = in->padlen;
        out->padding.insert(out->padding.end(), in->padding.data(), in->padding.data() + in->padding.size());
    }

    /** Copies all the common DepWeight fields from "in" to "out" */
    static void copy_depweight(DepWeight *in, DepWeight *out) {
        out->exclusive = in->exclusive;
        out->stream_dep = in->stream_dep;
        out->weight = in->weight;
    }

    /** Copies all the common Headers fields from "in" to "out" */
    static void copy_headers(Headers *in, Headers *out) {
        for (int i = 0; i < in->hdr_pairs.size(); ++i) {
            out->hdr_pairs.push_back(in->hdr_pairs[i]);
            out->prefixes.push_back(in->prefixes[i]);
            out->idx_types.push_back(in->idx_types[i]);
        }
    }

    /** Returns a new copy of the given DataFrame */
    static DataFrame* copy_dataframe(DataFrame *df) {
        auto *out = new DataFrame();
        copy_baseframe(df, out);
        copy_padded(df, out);

        out->data.insert(out->data.end(), df->data.data(), df->data.data()+df->data.size());
        return out;
    }

    /** Returns a new copy of the given HeadersFrame */
    static HeadersFrame* copy_headersframe(HeadersFrame *hf) {
        auto *out = new HeadersFrame();
        copy_baseframe(hf, out);
        copy_padded(hf, out);
        copy_depweight(hf, out);
        copy_headers(hf, out);
        return out;
    }

    /** Returns a new copy of the given PriorityFrame */
    static PriorityFrame* copy_priorityframe(PriorityFrame *pf) {
        auto *out = new PriorityFrame();
        copy_baseframe(pf, out);
        copy_depweight(pf, out);
        return out;
    }

    /** Returns a new copy of the given RstStreamFrame */
    static RstStreamFrame* copy_rst_streamframe(RstStreamFrame *rsf) {
        auto *out = new RstStreamFrame();
        copy_baseframe(rsf, out);
        out->error_code = rsf->error_code;
        return out;
    }

    /** Returns a new copy of the given SettingsFrame */
    static SettingsFrame* copy_settingsframe(SettingsFrame *sf) {
        auto *out = new SettingsFrame();
        copy_baseframe(sf, out);
        for (Setting s : sf->settings) {
            out->settings.push_back(s);
        }
        return out;
    }

    /** Returns a new copy of the given PushPromiseFrame */
    static PushPromiseFrame* copy_push_promiseframe(PushPromiseFrame *ppf) {
        auto *out = new PushPromiseFrame();
        copy_baseframe(ppf, out);
        copy_padded(ppf, out);
        copy_headers(ppf, out);
        out->reserved_pp = ppf->reserved_pp;
        out->prom_stream_id = ppf->prom_stream_id;
        return out;
    }

    /** Returns a new copy of the given PingFrame */
    static PingFrame* copy_pingframe(PingFrame *pf) {
        auto *out = new PingFrame();
        copy_baseframe(pf, out);
        out->data = pf->data;
        return out;
    }

    /** Returns a new copy of the given GoAwayFrame */
    static GoAway* copy_goaway(GoAway *ga) {
        auto *out = new GoAway();
        copy_baseframe(ga, out);
        out->reserved_ga = ga->reserved_ga;
        out->last_stream_id = ga->last_stream_id;
        out->error_code = ga->error_code;
        out->debug_data.insert(out->debug_data.end(), ga->debug_data.data(), ga->debug_data.data()+ga->debug_data.size());
        return out;
    }

    /** Returns a new copy of the given WindowUpdate */
    static WindowUpdate* copy_window_updateframe(WindowUpdate *wu) {
        auto *out = new WindowUpdate();
        copy_baseframe(wu, out);
        out->reserved_wu = wu->reserved_wu;
        out->win_sz_inc = wu->win_sz_inc;
        return out;
    }

    /** Returns a new copy of the given Continuation */
    static Continuation* copy_continuation(Continuation *c) {
        auto *out = new Continuation();
        copy_baseframe(c, out);
        copy_headers(c, out);
        return out;
    }
};
