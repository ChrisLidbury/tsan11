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
  ~Scheduler();

  // Performed here instead of constructor, as flags need to be initialised.
  void Initialise();

  // Get next number in a deterministic PRNG.
  // To preserve the deterministic replayability, only call this if:
  //   - It is in a visible instruciton.
  //   - It is the active thread.
  // Should not be called outside of testing.
  static u64 RandomNumber();

  // Tick the scheduler.
  // It will decide which thread should become active based on some strategy.
  void Tick(ThreadState *thr);
  // Block this thread until the scheduler allows it to run.
  void Wait(ThreadState *thr);

  // Update scheduler when threads change.
  void NewThread(ThreadState *thr, int tid);
  void DeleteThread(ThreadState *thr);
  void JoinThread(ThreadState *thr, int join_tid);

  // For demo playback and recording.
  // Helps verify that demo playback is in sync.
  // Easy access to demo recording.
  // Only call if this is the active thread.
  enum EventType { END = 0, SCHEDULE = 1, READ = 2 };
  u64 RandomNext(ThreadState *thr, EventType event_type);

 private:
  // When performing a blocking call, the thread should disable itself.
  void Enable(int tid);
  void Disable(int tid);

  // Parse next event from file during demo playback.
  void DemoNext();

  // Represents a deterministic time point for the program.
  // This changes on each tick, and should not differ when replaying.
  u64 tick_;

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

  // For disable/delete, the status of child/parent needs to be known.
  enum Status { FINISHED = 0, DISABLED = 1, RUNNING = 2 };
  Status thread_status_[kNumThreads];
  int wait_tid_[kNumThreads];

  // For demo playback.
  u64 demo_tick_;
  EventType event_type_;
  u64 event_param_;
  char *demo_contents_;
  // Demo record.
  fd_t record_fd_;
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
