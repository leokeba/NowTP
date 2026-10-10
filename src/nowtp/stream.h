// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <memory>
#include <vector>

#include "engine.h"

namespace nowtp {

/// Describes an incoming stream to the application.
struct StreamInfo {
    Mac peer;
    uint32_t id = 0;
    uint8_t topic = 0;    ///< Application-defined kind of stream, e.g. firmware.
    uint32_t size = 0;    ///< Total bytes.
    std::vector<uint8_t> header;  ///< Application data sent with the offer (version, hash...).
};

/// Supplies outgoing stream data: copy `len` bytes at `offset` into `buf`.
/// Called once per chunk, in order, so a sequential source (a download, a
/// flash partition) works. Return false to abort the stream.
using StreamReader = std::function<bool(uint32_t offset, uint8_t* buf, size_t len)>;
using StreamDone = std::function<void(Status)>;
using StreamProgress = std::function<void(uint32_t done, uint32_t total)>;

/// The receiving end of one stream, filled in by the application when it accepts.
struct StreamSink {
    /// Consumes the next bytes, strictly in order. Return false to abort.
    std::function<bool(uint32_t offset, const uint8_t* data, size_t len)> write;
    /// Called once: Ok when every byte arrived and the checksum matched;
    /// Cancelled if the sender gave up, Timeout if it went silent.
    StreamDone done;
};

/// Decides whether to accept a stream; fills in `sink` and returns true to accept.
using StreamAcceptor = std::function<bool(const StreamInfo& info, StreamSink& sink)>;

struct StreamOptions {
    uint8_t topic = 0;
    /// Delivered with the offer; at most kMaxHeader bytes.
    std::vector<uint8_t> header;
    /// Bytes per data message. Must fit the receiver's Config::maxMessageSize.
    uint32_t chunkSize = 4096;
    /// Data messages in flight. Two keep the radio busy while the previous
    /// chunk is acknowledged; the receiver holds at most window - 1 chunks
    /// that arrived early.
    uint8_t window = 2;
    /// Deadline for each step: the answer to the offer, each chunk, the result.
    uint32_t timeoutMs = 10000;
    /// Called as chunks are acknowledged, in the NowTP task.
    StreamProgress progress;
};

/// Transfers of any size (firmware images, files) on kStreamPort, without
/// holding them in memory: the sender pulls data from a StreamReader and the
/// receiver pushes it into a StreamSink as it arrives, in order.
///
/// A stream is offered to the receiver, which accepts or rejects it based on
/// its topic, size and header; the data then follows as reliable messages,
/// and a CRC-32 over the whole stream confirms the result. Platform-independent;
/// driven by tick(). Reader and sink callbacks run in the engine's context.
class Streams {
public:
    static constexpr size_t kMaxHeader = 200;
    static constexpr size_t kMaxOutgoing = 4;
    static constexpr size_t kMaxIncoming = 4;
    /// A receiver gives up on a sender silent for this long.
    static constexpr uint32_t kIdleTimeoutMs = 30000;

    Streams(Engine& engine, std::function<uint32_t()> random);
    ~Streams();

    Streams(const Streams&) = delete;
    Streams& operator=(const Streams&) = delete;

    void start();
    void stop();
    void tick(uint32_t nowMs);

    /// Starts sending `size` bytes to `dst`. `done` runs once with the outcome:
    /// Ok when the receiver confirmed the whole stream, Rejected if it refused
    /// or aborted, Timeout if it stopped answering.
    Status send(const Mac& dst, uint32_t size, StreamReader read, StreamDone done, const StreamOptions& options,
                uint32_t nowMs, uint32_t* id = nullptr);
    /// Aborts an outgoing stream; its `done` runs with Cancelled.
    Status cancel(uint32_t id, uint32_t nowMs);
    /// Sets the handler deciding about incoming streams (none: all rejected).
    void onIncoming(StreamAcceptor acceptor) { acceptor_ = std::move(acceptor); }

    size_t outgoing() const { return out_.size(); }
    size_t incoming() const { return in_.size(); }

private:
    enum MsgType : uint8_t {
        kOffer = 1,
        kAccept = 2,
        kReject = 3,
        kData = 4,
        kEnd = 5,
        kResult = 6,
        kAbort = 7,
    };

    struct Out;
    struct In;

    void handle(const Message& m);
    Out* findOut(uint32_t id);
    In* findIn(const Mac& src, uint32_t id);
    Status sendOffer(uint32_t id);
    void chunkDone(uint32_t id, uint32_t offset, Status status);
    void pump(uint32_t id);
    void finishOut(uint32_t id, Status status);
    void finishIn(const Mac& src, uint32_t id, Status status);
    void control(const Mac& dst, uint8_t type, uint32_t id, uint8_t value = 0, bool withValue = false);
    bool deliverChunk(In& in, const uint8_t* data, size_t len);

    Engine& engine_;
    std::function<uint32_t()> random_;
    StreamAcceptor acceptor_;
    std::vector<std::unique_ptr<Out>> out_;
    std::vector<std::unique_ptr<In>> in_;
    bool running_ = false;
    uint32_t now_ = 0;
};

}  // namespace nowtp
