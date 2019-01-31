// Random scheduler stuff.

#include "tsan_schedule.h"

#include "tsan_rtl.h"

namespace __tsan {
namespace {

// Condition variables each thread needs to wait on before proceeding.
// We don't want to use mutexes, as different thread will block and notify.
const int kInactive = 0;
const int kActive = 1;
const int kCritical = 2;
atomic_uintptr_t cond_vars_[Scheduler::kNumThreads];

// Allows O(1) acces to the currently active threads.
// cond_vars_idx_[rnd(0, last_free_idx_)] gives an active tid.
// cond_vars_idx_inv_[tid] with active tid gives its position cond_vars_idx_.
// All active tids at any point are packed in cond_vars_idx_.
int cond_vars_idx_[Scheduler::kNumThreads];
int cond_vars_idx_inv_[Scheduler::kNumThreads];
int last_free_idx_;

// Auxilliary info for the scheduling strategy.
// Prioity based scheduling. Slightly adjust when repeatedly rescheduling.
const int kMaxPri = -300;
const int kMinPri = 3;
int pri_[Scheduler::kNumThreads];

// Used by Reschedule() to see if the scheduler has been blocked for too long.
u64 reschedule_tick_;

// Pick a tid to become active based on some scheduling strategy.
// Must pass the random number in due to replay stuff.
int Schedule(u64 rnd) {
  if (last_free_idx_ == 0) {
    return 0;
  }
  if (last_free_idx_ == 1) {
    return cond_vars_idx_[0];
  }
  // Check if the rnd is a miss in the scheduling table.
  u64 row = rnd / last_free_idx_;
  int col = rnd % last_free_idx_;
  int pri = pri_[cond_vars_idx_[col]];
  int hit_rate = (pri < 0 ? -pri : pri) + 2;
  if (!(row % hit_rate > 0) != !(pri > 0)) {
    return cond_vars_idx_[col];
  }
  // rnd is a miss, row number is squashed and becomes new rnd.
  // Second lookup with new rnd ignores missed tid.
  u64 new_rnd = row / hit_rate;
  if (pri > 0) {
    new_rnd = row - new_rnd - 1;
  }
  int new_col = new_rnd % (last_free_idx_ - 1);
  if (new_col >= col) {
    ++new_col;
  }
  return cond_vars_idx_[new_col];
}

}  // namespace


// The functions below are still a part of the main scheduler.

void Scheduler::StrategyRandomInitialise() {
  WaitFunc       = &Scheduler::StrategyRandomWait;
  TickFunc       = &Scheduler::StrategyRandomTick;
  EnableFunc     = &Scheduler::StrategyRandomEnable;
  DisableFunc    = &Scheduler::StrategyRandomDisable;
  RescheduleFunc = &Scheduler::StrategyRandomReschedule;
  SignalWakeFunc = &Scheduler::StrategyRandomSignalWake;
  last_free_idx_ = 0;
  internal_memset(cond_vars_, kInactive, sizeof(cond_vars_));
  atomic_store(&cond_vars_[0], kActive, memory_order_relaxed);
  reschedule_tick_ = 0;
}

void Scheduler::StrategyRandomWait(ThreadState *thr) {
  /*uptr cmp = kActive;
  while (!atomic_compare_exchange_strong(
      &cond_vars_[thr->tid], &cmp, kCritical, memory_order_relaxed)) {
    CHECK(cmp == kInactive);
    cmp = kActive;
    ProcessPendingSignals(thr);  // Dangerous, must change.
    proc_yield(20);
  }*/
  BlockWait(thr->tid, &cond_vars_[thr->tid], kActive, kCritical,
      !signal_context_[thr->tid]);
}

void Scheduler::StrategyRandomTick(ThreadState *thr) {
  mtx.Lock();
  uptr cmp = kCritical;
  bool is_critical = atomic_compare_exchange_strong(
      &cond_vars_[thr->tid], &cmp, kInactive, memory_order_relaxed);
  CHECK(is_critical);
  // DEBUG
  if (print_trace) {
    Printf("%d - %d - ", thr->tid, tick_);
    PrintUserSanitizerStackBoundary();
    Printf("\n");
  }
  // If annotated out, immediately reenable this thread.
  if (exclude_point_[thr->tid] == 1 && thread_status_[thr->tid] != DISABLED) {
    atomic_store(&cond_vars_[thr->tid], kActive, memory_order_relaxed);
    mtx.Unlock();
    return;
  }

  if (pri_[thr->tid] > kMaxPri) {
    pri_[thr->tid] = kMaxPri;
  }
  // Select new thread, or same thread if there is still a time slice.
  int next_tid;
  if (slice_ > 1 && thread_status_[thr->tid] == RUNNING) {
    next_tid = thr->tid;
    --slice_;
  } else {
    next_tid = Schedule(RandomNumber());
    slice_ = slice_length;
  }
  // Replay any events that occured between this Tick() and the next Wait().
  DemoPlayPeekNext();
  while (DemoPlayActive() && tick_ == demo_play_.demo_tick_) {
    if (demo_play_.event_type_ == RESCHEDULE) {
      for (u64 re = demo_play_.event_param_; re > 0; --re) {
        if (pri_[next_tid] < kMinPri) {
          ++pri_[next_tid];
        }
        next_tid = Schedule(RandomNumber());
        slice_ = slice_length;
      }
    } else if (demo_play_.event_type_ == SIG_WAKEUP) {
      Enable(demo_play_.event_param_);
    } else {
      CHECK(false && "Unknown event type in replay.");
    }
    DemoRecordNext(tick_, demo_play_.event_type_, demo_play_.event_param_, 0);
    DemoPlayNext();
  }
  SignalPending(thr);

  // Activate chosen next tid.
  ++tick_;
  CHECK(thread_status_[next_tid] == RUNNING ||
      (next_tid == 0 && last_free_idx_ == 0));
  active_tid_ = next_tid;
  atomic_store(&cond_vars_[next_tid], kActive, memory_order_seq_cst/*memory_order_relaxed*/);
  BlockSignal(next_tid);
  mtx.Unlock();
  ProcessPendingSignals(thr);
}

void Scheduler::StrategyRandomEnable(int tid) {
  cond_vars_idx_[last_free_idx_] = tid;
  cond_vars_idx_inv_[tid] = last_free_idx_++;
  thread_status_[tid] = RUNNING;
  pri_[tid] = kMaxPri;
}

void Scheduler::StrategyRandomDisable(int tid) {
//CHECK(last_free_idx_ > 1 && "No runnable threads");
  int tid_last_idx = cond_vars_idx_[--last_free_idx_];
  cond_vars_idx_[cond_vars_idx_inv_[tid]] = tid_last_idx;
  cond_vars_idx_inv_[tid_last_idx] = cond_vars_idx_inv_[tid];
  thread_status_[tid] = DISABLED;
}

void Scheduler::StrategyRandomReschedule() {
  mtx.Lock();
  if (DemoPlayActive() || last_free_idx_ <= 1 || tick_ != reschedule_tick_ ||
      exclude_point_[active_tid_] == 1) {
    reschedule_tick_ = tick_;
    mtx.Unlock();
    return;
  }
  int tid = active_tid_;
  uptr cmp = kActive;
  bool is_active = atomic_compare_exchange_strong(
      &cond_vars_[tid], &cmp, kInactive, memory_order_relaxed);
  if (!is_active) {
    CHECK(cmp == kCritical);
    mtx.Unlock();
    return;
  }
  if (pri_[tid] < kMinPri) {
    ++pri_[tid];
  }
  int next_tid = Schedule(RandomNumber());
  slice_ = slice_length;
  CHECK(thread_status_[next_tid] == RUNNING);
  active_tid_ = next_tid;
  atomic_store(&cond_vars_[next_tid], kActive, memory_order_relaxed);
  BlockSignal(next_tid);
  DemoRecordOverride(tick_ - 1, RESCHEDULE, 1, 0);
  mtx.Unlock();
}

void Scheduler::StrategyRandomSignalWake(ThreadState *thr) {
  mtx.Lock();
  if (DemoPlayActive() || thread_status_[thr->tid] != DISABLED ||
      exclude_point_[active_tid_] == 1) {
    mtx.Unlock();
    return;
  }
  // Stop all threads as long as one is not critical.
  uptr cmp = kActive;
  for (;;) {
    if (atomic_compare_exchange_strong(
        &cond_vars_[active_tid_], &cmp, kInactive, memory_order_relaxed)) {
      break;
    }
    mtx.Unlock();
    proc_yield(20);
    cmp = kActive;
    mtx.Lock();
  }
  // It is possible that a thread unlocked this thread since the last check.
  if (thread_status_[thr->tid] != DISABLED) {
    mtx.Unlock();
    return;
  }
  // TODO may need to disable post signal.
  Enable(thr->tid);
  DemoRecordNext(tick_ - 1, SIG_WAKEUP, thr->tid, 0);
  atomic_store(&cond_vars_[active_tid_], kActive, memory_order_relaxed);
  BlockSignal(active_tid_);
  mtx.Unlock();
}

}  // namespace __tsan
