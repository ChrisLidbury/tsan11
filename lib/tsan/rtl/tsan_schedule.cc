#include "tsan_schedule.h"

#include "tsan_mutex.h"
#include "tsan_rtl.h"

namespace __tsan {

// Fetch the value in the tsc register (x86).
// Can be used as a random value (for the lower bits).
static inline u64 rdtsc() {
  u64 ret;
  asm volatile ("rdtsc; "          // read of tsc
                "shl $32,%%rdx; "  // shift higher 32 bits stored in rdx up
                "or %%rdx,%%rax"   // and or onto rax
                : "=a"(ret)        // output to tsc
                :
                : "%rcx", "%rdx", "memory"); // rcx and rdx are clobbered
                                             // memory to prevent reordering
  return ret;
}

// TODO change mutex stat type
Scheduler::Scheduler() : mtx(MutexTypeSchedule, StatMtxTotal) {
  internal_memset(cond_vars_, kInactive, sizeof(cond_vars_));
  last_free_idx_ = 0;
  // Setup start thread.
  // This thread will still call NewThread, so do not adjust last_free_idx_.
  atomic_store(&cond_vars_[0], kActive, memory_order_relaxed);
}

// Current thr must be active.
// Any available thread must become active.
// Locked due to DeleteThread and for synchronisation.
void Scheduler::Tick(ThreadState *thr) {
  mtx.Lock();
  uptr cmp = kActive;
  bool is_active =
      atomic_compare_exchange_strong(&cond_vars_[thr->tid],
                                     &cmp, kInactive, memory_order_relaxed);
  CHECK(is_active);
  if (last_free_idx_ == 0) {
    atomic_store(&cond_vars_[0], kActive, memory_order_relaxed);
  } else {
    int next_active = (rdtsc() >> 2) % last_free_idx_;
    atomic_store(&cond_vars_[cond_vars_idx_[next_active]], kActive, memory_order_relaxed);
  }
  mtx.Unlock();
}

// Must only check if it is active, not change it.
void Scheduler::Wait(ThreadState *thr) {
//  uptr cmp = kActive;
//  while (!atomic_compare_exchange_strong(&cond_vars_[thr->tid],
//                                         &cmp, kActive, memory_order_relaxed))
  while (atomic_load(&cond_vars_[thr->tid], memory_order_relaxed) != kActive)
    proc_yield(20);
}

// Wait and Tick are called here, unlike with atomics.
// The initial thread will call NewThread on itself, so should not be disabled.
void Scheduler::NewThread(ThreadState *thr, int tid) {
  Wait(thr);
  mtx.Lock();
  cond_vars_idx_[last_free_idx_] = tid;
  cond_vars_idx_inv_[tid] = last_free_idx_++;
  if (thr->tid != tid)
    atomic_store(&cond_vars_[tid], kInactive, memory_order_relaxed);
  mtx.Unlock();
  Tick(thr);
}

// Replace this threads position in the last with the last.
// Mark the one past the end as active so this thread can tick.
void Scheduler::DeleteThread(ThreadState *thr) {
  // There isn't an easy way to do this without the mutex.
  Wait(thr);
  mtx.Lock();
  int tid_last_idx = cond_vars_idx_[--last_free_idx_];
  cond_vars_idx_[cond_vars_idx_inv_[thr->tid]] = tid_last_idx;
  cond_vars_idx_inv_[tid_last_idx] = cond_vars_idx_inv_[thr->tid];
  mtx.Unlock();
  Tick(thr);
}

// This will typically wake up immediately after its child thread has called
// DeleteThread and Tick.
// TODO This causes non-determinism due to lack of Wait and Tick.
void Scheduler::Enable(ThreadState *thr) {
  mtx.Lock();
  cond_vars_idx_[last_free_idx_] = thr->tid;
  cond_vars_idx_inv_[thr->tid] = last_free_idx_++;
  mtx.Unlock();
}

void Scheduler::Disable(ThreadState *thr) {
  Wait(thr);
  mtx.Lock();
  int tid_last_idx = cond_vars_idx_[--last_free_idx_];
  cond_vars_idx_[cond_vars_idx_inv_[thr->tid]] = tid_last_idx;
  cond_vars_idx_inv_[tid_last_idx] = cond_vars_idx_inv_[thr->tid];
  mtx.Unlock();
  Tick(thr);
}

// Not yet available.
// Should take a callback and run: Wait -> Callback -> Tick.
void Schedule(ThreadState *thr) {
  CheckNoLocks(thr);
  ctx->scheduler.Wait(thr);
  // Callback to visible instruction here.
  ctx->scheduler.Tick(thr);
}

}  // namespace __tsan
