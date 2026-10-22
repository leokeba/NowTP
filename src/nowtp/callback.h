// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

#include <functional>
#include <memory>
#include <utility>

namespace nowtp {

/// A stored callback that may be replaced, even by itself, while it runs.
///
/// Copying a std::function before calling it (the usual guard) allocates when
/// its captures exceed the function's inline buffer, and on a short heap that
/// operator new aborts (exceptions are off on ESP-IDF). Copies of a Callback
/// share one target instead: a call keeps it alive by reference count, without
/// allocating. Setting one allocates, once, from whoever sets it.
template <class Signature>
class Callback;

template <class R, class... Args>
class Callback<R(Args...)> {
public:
    typedef std::function<R(Args...)> Function;

    Callback() {}
    Callback(Function f) { set(std::move(f)); }  // NOLINT: implicit, as std::function

    void set(Function f) { target_ = f ? std::make_shared<Function>(std::move(f)) : std::shared_ptr<Function>(); }
    void reset() { target_.reset(); }
    explicit operator bool() const { return static_cast<bool>(target_); }

    /// Must be set. The target lives until the call returns.
    R operator()(Args... args) const {
        std::shared_ptr<Function> keep = target_;
        return (*keep)(std::forward<Args>(args)...);
    }

private:
    std::shared_ptr<Function> target_;
};

/// Brackets each call of an application callback, so that its owner can let
/// go of its lock meanwhile: EspNowTransport does, so a callback may wait for
/// a task that is itself calling NowTP. Code around a gate must not rely on
/// state it read before: other tasks may call in while the callback runs, as
/// the callback itself may. enter() returns what the matching leave() needs.
class CallbackGate {
public:
    virtual ~CallbackGate() {}
    virtual uint32_t enter() = 0;
    virtual void leave(uint32_t token) = 0;
};

/// Holds a gate open for a scope; a null gate does nothing.
class GateScope {
public:
    explicit GateScope(CallbackGate* gate) : gate_(gate), token_(gate ? gate->enter() : 0) {}
    ~GateScope() {
        if (gate_) gate_->leave(token_);
    }
    GateScope(const GateScope&) = delete;
    GateScope& operator=(const GateScope&) = delete;

private:
    CallbackGate* gate_;
    uint32_t token_;
};

}  // namespace nowtp
