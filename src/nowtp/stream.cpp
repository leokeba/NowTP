// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#include "stream.h"

#include <algorithm>

namespace nowtp {

using wire::getU32;
using wire::putU32;

namespace {

constexpr size_t kDataHeader = 9;       // type, id, offset
constexpr size_t kOfferFixed = 15;      // type, id, size, chunk, topic, window
constexpr size_t kMaxHeldBytes = 64 * 1024;
// A reliable message can still fail, e.g. when the radio loses one frame
// three times in a row; over a long stream that happens, so steps are retried.
constexpr uint8_t kAttempts = 5;

enum ResultCode : uint8_t { kResultOk = 0, kResultChecksum = 1, kResultIncomplete = 2 };
enum RejectReason : uint8_t { kRefused = 0, kTooLarge = 1, kBusy = 2 };

inline bool reached(uint32_t now, uint32_t deadline) {
    return static_cast<int32_t>(now - deadline) >= 0;
}

SendOptions reliableWithin(uint32_t timeoutMs) {
    SendOptions o;
    o.reliable = true;
    o.timeoutMs = timeoutMs;
    return o;
}

}  // namespace

constexpr size_t Streams::kMaxHeader;
constexpr size_t Streams::kMaxOutgoing;
constexpr size_t Streams::kMaxIncoming;
constexpr uint32_t Streams::kIdleTimeoutMs;

struct Streams::Out {
    struct Chunk {
        uint32_t offset;
        std::vector<uint8_t> frame;  // data message, kept until acknowledged
        uint8_t attempts;
        bool queued;
    };
    uint32_t id = 0;
    Mac dst;
    uint32_t size = 0;
    StreamReader read;
    StreamDone done;
    StreamOptions options;
    enum Phase : uint8_t { Offering, Sending } phase = Offering;
    std::vector<uint8_t> offer;
    uint8_t offerAttempts = 0;
    uint32_t next = 0;       // next offset to read
    uint32_t confirmed = 0;  // bytes acknowledged
    uint32_t crc = 0;        // over the bytes read so far
    std::vector<Chunk> chunks;
    bool endQueued = false;
    uint8_t endAttempts = 0;
    uint32_t deadline = 0;
};

struct Streams::In {
    Mac src;
    uint32_t id = 0;
    uint32_t size = 0;
    uint32_t chunk = 0;
    uint8_t window = 1;
    uint32_t expected = 0;
    uint32_t crc = 0;
    StreamSink sink;
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> held;  // chunks that arrived early
    uint32_t lastActivity = 0;
};

Streams::Streams(Engine& engine, std::function<uint32_t()> random) : engine_(engine), random_(std::move(random)) {
    if (!random_) random_ = [] { return 1u; };
}

Streams::~Streams() {
    stop();
}

void Streams::start() {
    running_ = true;
    engine_.listen(kStreamPort, [this](const Message& m) { handle(m); });
}

void Streams::stop() {
    if (!running_) return;
    engine_.listen(kStreamPort, ReceiveHandler());
    running_ = false;
    while (!out_.empty()) finishOut(out_.front()->id, Status::Cancelled);
    while (!in_.empty()) finishIn(in_.front()->src, in_.front()->id, Status::Cancelled);
}

Streams::Out* Streams::findOut(uint32_t id) {
    for (auto& o : out_) {
        if (o->id == id) return o.get();
    }
    return nullptr;
}

Streams::In* Streams::findIn(const Mac& src, uint32_t id) {
    for (auto& i : in_) {
        if (i->id == id && i->src == src) return i.get();
    }
    return nullptr;
}

void Streams::control(const Mac& dst, uint8_t type, uint32_t id, uint8_t value, bool withValue) {
    uint8_t msg[6];
    msg[0] = type;
    putU32(msg + 1, id);
    msg[5] = value;
    engine_.send(dst, kStreamPort, msg, withValue ? 6 : 5, reliableWithin(5000), CompletionHandler(), now_);
}

// ---------------------------------------------------------------------------
// Sending

Status Streams::send(const Mac& dst, uint32_t size, StreamReader read, StreamDone done, const StreamOptions& options,
                     uint32_t now, uint32_t* idOut) {
    now_ = now;
    if (!running_) return Status::InvalidState;
    if (dst.isBroadcast() || !read || options.header.size() > kMaxHeader || options.chunkSize == 0 ||
        options.window == 0) {
        return Status::InvalidArgument;
    }
    if (options.chunkSize + kDataHeader > engine_.config().maxMessageSize) return Status::TooLarge;
    if (out_.size() >= kMaxOutgoing) return Status::QueueFull;

    std::unique_ptr<Out> o(new Out());
    do {
        o->id = random_();
    } while (o->id == 0 || findOut(o->id));
    o->dst = dst;
    o->size = size;
    o->read = std::move(read);
    o->done = std::move(done);
    o->options = options;

    o->offer.resize(kOfferFixed + options.header.size());
    o->offer[0] = kOffer;
    putU32(o->offer.data() + 1, o->id);
    putU32(o->offer.data() + 5, size);
    putU32(o->offer.data() + 9, options.chunkSize);
    o->offer[13] = options.topic;
    o->offer[14] = options.window;
    if (!options.header.empty()) memcpy(o->offer.data() + kOfferFixed, options.header.data(), options.header.size());
    uint32_t id = o->id;
    out_.push_back(std::move(o));
    Status st = sendOffer(id);
    if (st != Status::Ok) {
        // Not started: report through the return value only.
        for (size_t i = 0; i < out_.size(); ++i) {
            if (out_[i]->id == id) out_.erase(out_.begin() + static_cast<std::ptrdiff_t>(i));
        }
        return st;
    }
    if (idOut) *idOut = id;
    return Status::Ok;
}

Status Streams::sendOffer(uint32_t id) {
    Out* o = findOut(id);
    if (!o) return Status::InvalidState;
    o->offerAttempts++;
    o->deadline = now_ + 2 * o->options.timeoutMs;  // the engine reports a lost offer first
    return engine_.send(o->dst, kStreamPort, o->offer.data(), o->offer.size(), reliableWithin(o->options.timeoutMs),
                        [this, id](Status s) {
                            Out* x = findOut(id);
                            if (!x || x->phase != Out::Offering) return;
                            if (s == Status::Ok) {
                                x->deadline = now_ + x->options.timeoutMs;  // for the answer
                                return;
                            }
                            if (s == Status::Rejected || x->offerAttempts >= kAttempts || sendOffer(id) != Status::Ok) {
                                finishOut(id, s);
                            }
                        },
                        now_);
}

Status Streams::cancel(uint32_t id, uint32_t now) {
    now_ = now;
    Out* o = findOut(id);
    if (!o) return Status::InvalidArgument;
    control(o->dst, kAbort, id);
    finishOut(id, Status::Cancelled);
    return Status::Ok;
}

void Streams::chunkDone(uint32_t id, uint32_t offset, Status s) {
    Out* o = findOut(id);
    if (!o) return;
    size_t i = 0;
    while (i < o->chunks.size() && o->chunks[i].offset != offset) ++i;
    if (i == o->chunks.size()) return;
    if (s == Status::Ok) {
        o->confirmed += static_cast<uint32_t>(o->chunks[i].frame.size() - kDataHeader);
        o->chunks.erase(o->chunks.begin() + static_cast<std::ptrdiff_t>(i));
        if (o->options.progress) {
            StreamProgress p = o->options.progress;
            p(o->confirmed, o->size);
        }
    } else if (s == Status::Rejected || s == Status::Cancelled || s == Status::AuthFailed ||
               o->chunks[i].attempts >= kAttempts) {
        control(o->dst, kAbort, id);
        finishOut(id, s);
        return;
    } else {
        o->chunks[i].queued = false;  // send it again; the receiver ignores a duplicate
    }
    pump(id);
}

void Streams::pump(uint32_t id) {
    for (;;) {
        Out* o = findOut(id);
        if (!o || o->phase != Out::Sending) return;

        if (o->confirmed == o->size && o->chunks.empty()) {
            if (o->endQueued) return;
            uint8_t end[9];
            end[0] = kEnd;
            putU32(end + 1, id);
            putU32(end + 5, o->crc);
            o->endAttempts++;
            Status st = engine_.send(o->dst, kStreamPort, end, sizeof(end), reliableWithin(o->options.timeoutMs),
                                     [this, id](Status s) {
                                         Out* x = findOut(id);
                                         if (!x) return;
                                         if (s == Status::Ok) {
                                             x->deadline = now_ + x->options.timeoutMs;  // for the result
                                             return;
                                         }
                                         if (s == Status::Rejected || x->endAttempts >= kAttempts) {
                                             finishOut(id, s);
                                             return;
                                         }
                                         x->endQueued = false;  // tick() sends it again
                                     },
                                     now_);
            if (st == Status::QueueFull) return;  // tick() retries
            o = findOut(id);
            if (!o) return;
            if (st != Status::Ok) {
                finishOut(id, st);
                return;
            }
            o->endQueued = true;
            o->deadline = now_ + 2 * o->options.timeoutMs;
            return;
        }

        Out::Chunk* c = nullptr;
        for (Out::Chunk& x : o->chunks) {
            if (!x.queued) {
                c = &x;
                break;
            }
        }
        if (!c) {
            // At most `window` chunks past the oldest unacknowledged one, so
            // the receiver never holds more than window - 1 early chunks.
            uint64_t span = o->chunks.empty() ? 0 : o->next - o->chunks.front().offset;
            if (o->next >= o->size || span >= static_cast<uint64_t>(o->options.window) * o->options.chunkSize) return;
            uint32_t len = std::min(o->options.chunkSize, o->size - o->next);
            Out::Chunk fresh;
            fresh.offset = o->next;
            fresh.attempts = 0;
            fresh.queued = false;
            fresh.frame.resize(kDataHeader + len);
            fresh.frame[0] = kData;
            putU32(fresh.frame.data() + 1, id);
            putU32(fresh.frame.data() + 5, o->next);
            if (!o->read(o->next, fresh.frame.data() + kDataHeader, len)) {
                control(o->dst, kAbort, id);
                finishOut(id, Status::Cancelled);
                return;
            }
            o = findOut(id);  // the reader may have cancelled the stream
            if (!o) return;
            o->crc = wire::crc32(fresh.frame.data() + kDataHeader, len, o->crc);
            o->next += len;
            o->chunks.push_back(std::move(fresh));
            continue;
        }

        uint32_t offset = c->offset;
        Status st = engine_.send(o->dst, kStreamPort, c->frame.data(), c->frame.size(),
                                 reliableWithin(o->options.timeoutMs),
                                 [this, id, offset](Status s) { chunkDone(id, offset, s); }, now_);
        if (st == Status::QueueFull) return;  // tick() retries
        o = findOut(id);
        if (!o) return;
        if (st != Status::Ok) {
            finishOut(id, st);
            return;
        }
        for (Out::Chunk& x : o->chunks) {
            if (x.offset != offset) continue;
            x.queued = true;
            x.attempts++;
        }
    }
}

void Streams::finishOut(uint32_t id, Status status) {
    for (size_t i = 0; i < out_.size(); ++i) {
        if (out_[i]->id != id) continue;
        std::unique_ptr<Out> o = std::move(out_[i]);  // detach, then call
        out_.erase(out_.begin() + static_cast<std::ptrdiff_t>(i));
        if (o->done) o->done(status);
        return;
    }
}

// ---------------------------------------------------------------------------
// Receiving

bool Streams::deliverChunk(In& in, const uint8_t* data, size_t len) {
    if (in.expected + len > in.size) return false;
    if (in.sink.write && !in.sink.write(in.expected, data, len)) return false;
    in.crc = wire::crc32(data, len, in.crc);
    in.expected += static_cast<uint32_t>(len);
    return true;
}

void Streams::finishIn(const Mac& src, uint32_t id, Status status) {
    for (size_t i = 0; i < in_.size(); ++i) {
        if (in_[i]->id != id || in_[i]->src != src) continue;
        std::unique_ptr<In> s = std::move(in_[i]);
        in_.erase(in_.begin() + static_cast<std::ptrdiff_t>(i));
        if (s->sink.done) s->sink.done(status);
        return;
    }
}

void Streams::handle(const Message& m) {
    if (m.len < 5) return;
    const uint8_t* d = m.data;
    uint32_t id = getU32(d + 1);
    switch (d[0]) {
        case kOffer: {
            if (m.len < kOfferFixed) return;
            if (findIn(m.src, id)) {
                control(m.src, kAccept, id);  // our accept was lost
                return;
            }
            StreamInfo info;
            info.peer = m.src;
            info.id = id;
            info.size = getU32(d + 5);
            uint32_t chunk = getU32(d + 9);
            info.topic = d[13];
            uint8_t window = d[14];
            info.header.assign(d + kOfferFixed, d + m.len);
            if (chunk == 0 || window == 0 || chunk + kDataHeader > engine_.config().maxMessageSize ||
                static_cast<size_t>(window - 1) * chunk > kMaxHeldBytes) {
                control(m.src, kReject, id, kTooLarge, true);
                return;
            }
            if (in_.size() >= kMaxIncoming) {
                control(m.src, kReject, id, kBusy, true);
                return;
            }
            StreamSink sink;
            StreamAcceptor acceptor = acceptor_;
            if (!acceptor || !acceptor(info, sink)) {
                control(m.src, kReject, id, kRefused, true);
                return;
            }
            std::unique_ptr<In> in(new In());
            in->src = m.src;
            in->id = id;
            in->size = info.size;
            in->chunk = chunk;
            in->window = window;
            in->sink = std::move(sink);
            in->lastActivity = now_;
            in_.push_back(std::move(in));
            control(m.src, kAccept, id);
            return;
        }
        case kAccept: {
            Out* o = findOut(id);
            if (!o || o->dst != m.src || o->phase != Out::Offering) return;
            o->phase = Out::Sending;
            pump(id);
            return;
        }
        case kReject:
        case kAbort: {
            Out* o = findOut(id);
            if (o && o->dst == m.src) {
                finishOut(id, Status::Rejected);
                return;
            }
            if (d[0] == kAbort && findIn(m.src, id)) finishIn(m.src, id, Status::Cancelled);
            return;
        }
        case kData: {
            if (m.len < kDataHeader) return;
            In* in = findIn(m.src, id);
            if (!in) {
                control(m.src, kAbort, id);  // e.g. we restarted: tell the sender at once
                return;
            }
            in->lastActivity = now_;
            uint32_t offset = getU32(d + 5);
            const uint8_t* data = d + kDataHeader;
            size_t len = m.len - kDataHeader;
            if (len == 0 || len > in->chunk || offset < in->expected) return;  // duplicate
            if (offset > in->expected) {
                bool known = false;
                for (const auto& h : in->held) known = known || h.first == offset;
                if (known) return;
                if (in->held.size() + 1 >= in->window) {
                    control(m.src, kAbort, id);
                    finishIn(m.src, id, Status::Rejected);
                    return;
                }
                in->held.push_back(std::make_pair(offset, std::vector<uint8_t>(data, data + len)));
                return;
            }
            bool ok = deliverChunk(*in, data, len);
            for (bool progress = ok; progress && ok;) {
                progress = false;
                for (size_t i = 0; i < in->held.size(); ++i) {
                    if (in->held[i].first != in->expected) continue;
                    std::vector<uint8_t> chunk;
                    chunk.swap(in->held[i].second);
                    in->held.erase(in->held.begin() + static_cast<std::ptrdiff_t>(i));
                    ok = deliverChunk(*in, chunk.data(), chunk.size());
                    progress = true;
                    break;
                }
            }
            if (!ok) {
                control(m.src, kAbort, id);
                finishIn(m.src, id, Status::Rejected);
            }
            return;
        }
        case kEnd: {
            if (m.len < 9) return;
            In* in = findIn(m.src, id);
            if (!in) return;
            uint8_t code = kResultOk;
            if (in->expected != in->size) {
                code = kResultIncomplete;
            } else if (getU32(d + 5) != in->crc) {
                code = kResultChecksum;
            }
            control(m.src, kResult, id, code, true);
            finishIn(m.src, id, code == kResultOk ? Status::Ok : Status::Rejected);
            return;
        }
        case kResult: {
            if (m.len < 6) return;
            Out* o = findOut(id);
            if (!o || o->dst != m.src || !o->endQueued) return;
            finishOut(id, d[5] == kResultOk ? Status::Ok : Status::Rejected);
            return;
        }
        default: return;
    }
}

void Streams::tick(uint32_t now) {
    now_ = now;
    if (!running_) return;
    for (size_t i = 0; i < out_.size(); ++i) {
        Out* o = out_[i].get();
        uint32_t id = o->id;
        bool waiting = o->phase == Out::Offering || o->endQueued;  // for the receiver's answer
        if (waiting && reached(now, o->deadline)) {
            finishOut(id, Status::Timeout);
            --i;
            continue;
        }
        if (o->phase == Out::Sending) pump(id);
        if (i < out_.size() && out_[i]->id != id) --i;  // finished meanwhile
    }
    for (size_t i = 0; i < in_.size(); ++i) {
        if (reached(now, in_[i]->lastActivity + kIdleTimeoutMs)) {
            finishIn(in_[i]->src, in_[i]->id, Status::Timeout);
            --i;
        }
    }
}

}  // namespace nowtp
