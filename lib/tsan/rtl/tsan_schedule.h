// Scheduler for tsan11 that controls the following:
//   - Which thread can execute a pending visible instruction.
//   - Which store a load can read from.

#ifndef TSAN_SCHEDULE_H_
#define TSAN_SCHEDULE_H_

#include "sanitizer_common/sanitizer_atomic.h"
#include "tsan_defs.h"
#include "tsan_mutex.h"

namespace __tsan {

// Controls scheduling, waking of threads and history.
class Scheduler {
 public:
  Scheduler();

  // Tick the scheduler.
  // It will decide which thread should become active based on some strategy.
  void Tick(ThreadState *thr);
  // Block this thread until the scheduler allows it to run.
  void Wait(ThreadState *thr);

  // Update scheduler when threads change.
  void NewThread(ThreadState *thr, int tid);
  void DeleteThread(ThreadState *thr);

  // When performing a blocking call, the thread should disable itself.
  void Disable(ThreadState *thr);
  void Enable(ThreadState *thr);
 private:
  // Serves two purposes: check for concurrent accesses and synchronisation.
  // There should be no contention for this mutex.
  Mutex mtx;
  // Condition variables each thread needs to wait on before proceeding.
  // We don't want to use mutexes, as different thread will block and notify.
  // We want a compacted array of active threads so we can easily see which
  // threads are used and easily select one at random.
  static const int kNumThreads = 80;
  static const int kInactive = 0;
  static const int kActive = 1;

  atomic_uintptr_t cond_vars_[kNumThreads];
  int cond_vars_idx_[kNumThreads];
  int cond_vars_idx_inv_[kNumThreads];
  int last_free_idx_;
};

// Main call into the scheduler. Should be called before a visible instruction.
//
// From the POV of the thread, calling this will do nothing. It will simply
// return without side effects. The scheduler will block the thread until it is
// OK to continue.
//
// Scheduling comes in two parts:
//   - The scheduler subsystem ticks in the thread that called schedule. As only
//     one thread is active at any time, so there should be no concurrent calls
//     to the ticker.
//   - The thread is blocked until the subsystem says it is allowed to run.
void Schedule(ThreadState *thr);

}  // namespace __tsan

#endif  // TSAN_SCHEDULE_H_
