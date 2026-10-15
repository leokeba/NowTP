// NowTP - transport protocol over ESP-NOW
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdlib>
#include <new>

#include "heap.h"
#include <utility>
#include <vector>

namespace nowtp {

/// Up to `limit` entries, each malloc()ed when added. Memory follows what is
/// stored, and a short heap refuses an addition instead of aborting, as
/// std::vector growth would with exceptions off (ESP-IDF). Only the array of
/// pointers is reserved up front: one pointer per allowed entry.
template <class T>
class Table {
public:
    explicit Table(size_t limit) : limit_(limit) { items_.reserve(limit); }
    ~Table() { clear(); }
    Table(const Table&) = delete;
    Table& operator=(const Table&) = delete;

    size_t size() const { return items_.size(); }
    bool empty() const { return items_.empty(); }
    bool full() const { return items_.size() >= limit_; }
    T& operator[](size_t i) { return *items_[i]; }
    const T& operator[](size_t i) const { return *items_[i]; }

    /// Adds `value` at the end; null if full or out of memory.
    T* add(T value) {
        if (full()) return nullptr;
        void* p = heap::allocate(sizeof(T));
        if (!p) return nullptr;
        T* item = new (p) T(std::move(value));
        items_.push_back(item);  // within the reserved capacity
        return item;
    }
    void erase(size_t i) {
        destroy(items_[i]);
        items_.erase(items_.begin() + static_cast<std::ptrdiff_t>(i));
    }
    void clear() {
        for (T* item : items_) destroy(item);
        items_.clear();
    }

    template <class V, class P>
    struct Iter {
        P* p;
        V& operator*() const { return **p; }
        V* operator->() const { return *p; }
        Iter& operator++() {
            ++p;
            return *this;
        }
        bool operator!=(const Iter& o) const { return p != o.p; }
    };
    typedef Iter<T, T* const> iterator;
    typedef Iter<const T, T* const> const_iterator;
    iterator begin() { return iterator{items_.data()}; }
    iterator end() { return iterator{items_.data() + items_.size()}; }
    const_iterator begin() const { return const_iterator{items_.data()}; }
    const_iterator end() const { return const_iterator{items_.data() + items_.size()}; }

private:
    static void destroy(T* item) {
        item->~T();
        heap::release(item);
    }

    size_t limit_;
    std::vector<T*> items_;
};

}  // namespace nowtp
