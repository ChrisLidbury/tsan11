//===-- tsan_clock.h --------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
//===----------------------------------------------------------------------===//
#ifndef TSAN_CLOCK_H
#define TSAN_CLOCK_H

#include "tsan_defs.h"
#include "tsan_dense_alloc.h"

namespace __tsan {

struct ClockElem {
  u64 epoch  : kClkBits;
  u64 reused : 64 - kClkBits;
};

struct ClockBlock {
  static const uptr kSize = 512;
  static const uptr kTableSize = kSize / sizeof(u32);
  static const uptr kClockCount = kSize / sizeof(ClockElem);

  union {
    u32       table[kTableSize];
    ClockElem clock[kClockCount];
  };

  ClockBlock() {
  }
};

typedef DenseSlabAlloc<ClockBlock, 1<<16, 1<<10> ClockAlloc;
typedef DenseSlabAllocCache ClockCache;

// Vector of Vector Clocks for the RMW release sequence tracking.
// When a new thread performs a RMW with release, add mapping from tid -> VC and
// release the thread's clock to it.
// When there is a non-RMW of any kind, collapse VVC to just the VC of the
// performing thread, or empty everything.
//
// Associativity and mem management is difficult, so handle everything linearly
// for now.
//
// ThreadClock will handle it, so the SyncClock will have the VVC inside it.
struct VClockBlock {
  static const int kNumElems = 80;  // Limit VVC to 10 for now.

  VClockBlock() {}
  ~VClockBlock() {}

  u32 clocks_[kNumElems];
  unsigned tids_[kNumElems];
  u32 sizes_[kNumElems];
  unsigned last_free_idx_;
};

typedef DenseSlabAlloc<VClockBlock, 1<<16, 1<<10> VClockAlloc;
typedef DenseSlabAllocCache VClockCache;

// The clock that lives in sync variables (mutexes, atomics, etc).
// TODO: Shallow version for just the tab, allowing us to save space.
//       (no VVC, just a tab).
class SyncClock {
 public:
  SyncClock();
  ~SyncClock();

  // Copies the current state of the clock into dest. Ignores the VVC.
  void CopyClock(ClockCache *c, VClockCache *vc, SyncClock *dst) const;
  // Joins the clock in src with this, becoming the piecewise maximum.
  void JoinClock(ClockCache *c, SyncClock *src);

  uptr size() const {
    return size_;
  }

  u64 get(unsigned tid) const {
    return elem(tid).epoch;
  }

  void Resize(ClockCache *c, uptr nclk);
  void Reset(ClockCache *c, VClockCache *vc);

  void DebugDump(int(*printf)(const char *s, ...));

 private:
  friend struct ThreadClock;
  static const uptr kDirtyTids = 2;

  unsigned release_store_tid_;
  unsigned release_store_reused_;
  unsigned dirty_tids_[kDirtyTids];
  // tab_ contains indirect pointer to a 512b block using DenseSlabAlloc.
  // If size_ <= 64, then tab_ points to an array with 64 ClockElem's.
  // Otherwise, tab_ points to an array with 128 u32 elements,
  // each pointing to the second-level 512b block with 64 ClockElem's.
  ClockBlock *tab_;
  u32 tab_idx_;
  u32 size_;

  // For RMWs. if multiple RSs are created, use the VCC.
  VClockBlock *vclock_;
  u32 vclock_idx_;
  bool vvc_in_use_;

  ClockElem &elem(unsigned tid) const;
};

// The clock that lives in threads.
struct ThreadClock {
 public:
  typedef DenseSlabAllocCache Cache;

  explicit ThreadClock(unsigned tid, unsigned reused = 0);

  u64 get(unsigned tid) const {
    DCHECK_LT(tid, kMaxTidInClock);
    return clk_[tid].epoch;
  }

  void set(unsigned tid, u64 v);

  void set(u64 v) {
    DCHECK_GE(v, clk_[tid_].epoch);
    clk_[tid_].epoch = v;
  }

  void tick() {
    clk_[tid_].epoch++;
  }

  uptr size() const {
    return nclk_;
  }

  void acquire(ClockCache *c, const SyncClock *src);
  void release(ClockCache *c, VClockCache *vc, SyncClock *dst) const;
  void acq_rel(ClockCache *c, VClockCache *vc, SyncClock *dst);
  void ReleaseStore(ClockCache *c, VClockCache *vc, SyncClock *dst) const;

  // Extras for RS support, we let thread clock code handle it.
  void NonReleaseStore(ClockCache *c, VClockCache *vc, SyncClock *dst, SyncClock *Frel_clock) const;
  void NonReleaseStore2(ClockCache *c, VClockCache *vc, SyncClock *dst, SyncClock *Frel_clock) const;  // Merge with 1.
  void RMW(ClockCache *c, VClockCache *vc, SyncClock *dst, bool is_acquire, bool is_release, SyncClock *Facq_clock, SyncClock *Frel_clock);
  void FenceRelease(ClockCache *c, VClockCache *vc, SyncClock *dst);
  void FenceAcquire(ClockCache *c, VClockCache *vc, SyncClock *src);

  void DebugReset();
  void DebugDump(int(*printf)(const char *s, ...));

 private:
  static const uptr kDirtyTids = SyncClock::kDirtyTids;
  const unsigned tid_;
  const unsigned reused_;
  u64 last_acquire_;
  uptr nclk_;
  ClockElem clk_[kMaxTidInClock];

  bool IsAlreadyAcquired(const SyncClock *src) const;
  void UpdateCurrentThread(SyncClock *dst) const;
};

}  // namespace __tsan

#endif  // TSAN_CLOCK_H
