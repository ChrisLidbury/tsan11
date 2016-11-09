#ifndef TSAN_RELAXED_H_
#define TSAN_RELAXED_H_

#include "tsan_clock.h"
#include "tsan_defs.h"
#include "tsan_dense_alloc.h"

namespace __tsan {

// To be able to properly abide CoRR, certain loads must be buffered (the
// alternative being to have a registry of SyncVars and updating on sync).
//
// Loads will be attached to individual stores in the store buffer, signifying
// that the thread read the value at the given epoch. The store buffer will have
// a list of actively updating loads for each tid.
//
// Notes:
// - Two loads by the same thread without a release store inbetween do not need
//   to be stored separately, as no other thread can possibly be constrained by
//   the first load.
// - The latest loads by a thread are still attached to the store elems, as
//   although no thread can be constrained by them at that point, when a release
//   store is performed, we may not get a chance to update it before another
//   thread tries to load.
// - It is safe to delete loads that are attached to a store being flushed.
// - A load does not need to be created when a store occurs (indicating that we
//   'read' the value we just stored) as the VC algorithm will ensure
//   consistency.
//
// With these in mind, we can say the following about how to handle the loads:
// - A load must be comitted when the last release performed by tid happens
//   after the load: if (thr->last_release > load->epoch_).
// - A store of any kind allows us to ditch the load, as the constraint imposed
//   will be picked up by the epoch within the StoreElem.
// - It is possible that a store can have multiple loads from the same tid
//   attached to it. The second load is redundant, as if the second load
//   constrains a thread, the first load will.
// - To help reduce the amount of loads, if there is a load at the end of mo
//   that must be comitted, it can instead be 'frozen', it will not be updated
//   or comitted until another store occurs, whereby it will be comitted.
struct StoreElem;
struct LoadElem {
  // Linked list, this creates quite an overhead, but is required.
  LoadElem *next_;
  LoadElem *prev_;
  StoreElem *store_;
  // Alloc id, for memory management.
  u32 id_;
  // tid and epoch pair.
  unsigned tid_;
  u64 epoch_;
};

typedef DenseSlabAlloc<LoadElem, 1<<16, 1<<10> LoadAlloc;
typedef DenseSlabAllocCache LoadCache;

// A single store performed by some thread.
struct StoreElem {
  // Linked list. Could use circular buffer instead.
  StoreElem *next_;
  StoreElem *prev_;
  // Alloc id, for memory management.
  u32 id_;
  // Position in modification order.
  u32 pos_;
  // Clock elem of tid_ when store was performed.
  u64 epoch_;
  // VC to acquire if acquire loads this value. TODO: Avoid SyncClock.
  SyncClock clock_;
  // Store params.
  unsigned tid_;
  bool is_sc_access_;
  u64 value_;  // Not templated, as this would affect too much.
  // Attached loads.
  LoadElem *loads_;
};

typedef DenseSlabAlloc<StoreElem, 1<<16, 1<<10> StoreAlloc;
typedef DenseSlabAllocCache StoreCache;

struct StoreBuffer {
  StoreBuffer();
  // Should be called before use to clear any prevous state.
  void Reset(Processor *proc);

  // Add and remove loads from load lists.
  // Passing store as 0 will add the load to the list at the end of mo.
  void RemoveLoadFromList(LoadElem *load);
  void AddLoadToList(LoadElem *load, StoreElem *store);

  // Push current state of the location (before the store) into the buffer.
  // This should be called by store functions before any update is performed.
  // is_sc_access indicates if the store about to be performed is sequentially
  // consistent, NOT the store about to be put in the buffer.
  void BufferStore(ThreadState *thr, u64 bits, SyncClock *clock,
                   bool is_sc_access, bool is_release);

  // Fetch value from store. Return false if no value is returned.
  bool FetchStore(ThreadState *thr, u64 *val, SyncClock **clock,
                  bool is_sc_access, bool is_release);

  // Sets thr's position in mo to the end.
  void AdvanceToEnd(ThreadState *thr);

  // Remove unnecessary stores from the back of the buffer.
  void FlushStores(ThreadState *thr);

  // Linked list of ordered stores.
  static const int kBuffMaxSize = 128;
  StoreElem *stores_;
  StoreElem *stores_back_;

  // Coherence.
  // Vector Position (VP) of current mo position for each thread.
  // Temporary static vector, until a proper VP is made;
  static const int kVPSize = 80;
  u32 pos_[kVPSize];
  u32 last_pos_;
  u32 size_;  // unused

  // Coherence.
  // Track the last store that has not yet been comitted.
  LoadElem *loads_[kVPSize];

  // Hack. Store info for the last load, when it is put into the buffer, it
  // won't be available.
  // TODO properly set on initialisation.
  unsigned prev_tid_;
  bool prev_is_sc_access_;
  u64 prev_epoch_;
  LoadElem *prev_loads_;
};

}  // namespace __tsan

#endif  // TSAN_RELAXED_H_
