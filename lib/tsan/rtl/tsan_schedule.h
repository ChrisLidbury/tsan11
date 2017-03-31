// Scheduler for tsan11 that controls the following:
//   - Which thread can execute a pending visible instruction.
//   - Which store a load can read from.

#ifndef TSAN_SCHEDULE_H_
#define TSAN_SCHEDULE_H_

#include "sanitizer_common/sanitizer_atomic.h"
#include "tsan_defs.h"
#include "tsan_mutex.h"

namespace __tsan {

struct ShmProcess;

// Controls scheduling, waking of threads and history.
class Scheduler {
 public:
  Scheduler();
  ~Scheduler();

  // Performed here instead of constructor, as flags need to be initialised.
  void Initialise();

  // Get next number in a deterministic PRNG.
  // To preserve the deterministic replayability, only call this if:
  //   - It is in a visible instruction.
  //   - It is the active thread.
  // Should not be called otherwise outside of testing.
  static u64 RandomNumber();


  ////////////////////////////////////////
  // Core ordering functions.
  // Can be used internally or externally to enforce orderings.
  ////////////////////////////////////////

  // Inter-thread scheduling functions.
  // It will decide which thread should become active based on some strategy.
  void Tick(ThreadState *thr);
  // Block this thread until the scheduler allows it to run.
  void Wait(ThreadState *thr);

  // Inter-process scheduling functions.
  // Similar to inter-thread ordering, but first come first serve.
  // Is a particular event ordered across processes.
  //bool ProcessEventIsOrdered(EventType event_type);  // TODO
  void ProcessWait();


  ////////////////////////////////////////
  // Event specific interface functions.
  // Called from outside on particular cases that require ordering.
  ////////////////////////////////////////

  // Thread update functions.
  // Change scheduler when threads change.
  void ThreadNew(ThreadState *thr, int tid);
  void ThreadDelete(ThreadState *thr);
  void ThreadJoin(ThreadState *thr, int join_tid);

  // All cond calls should be treated as visible instructions, thus, do the
  // usual Wait'n'Tick. The sleep is also controlled by the scheduler, allowing
  // us to deterministically choose the thread to signal.
  //
  // A thread doing a wait with timeout is not disabled, but can still eat up a
  // signal provided it has not done anything that happens after the signal.
  void CondWait(ThreadState *thr, void *c, bool timed);
  void CondSignal(ThreadState *thr, void *c);
  void CondBroadcast(ThreadState *thr, void *c);

  // Forking off processes is also deterministic.
  // For demo record/replay, a simple high level scheduler is used to ensure
  // they are created in the same order and that they get their own demo file,
  // that is assigned correctly when replying.
  // Each process created has its own id, that is the same as the demo file it
  // will read from. This will be acquired from a section of shared memory.
  u64 ForkBefore(ThreadState *thr);
  void ForkAfterParent(ThreadState *thr);
  void ForkAfterChild(ThreadState *thr, u64 id);

  // File stuff uuuggghhhghghghhhhh.
  // For demo playback, each process has its own file system to replay from.
  // For normal files, this will just be a stream of what was originally read.
  // For memory map, this will be the original contents of the mapped memory.
  // Other file stuff (pipes, etc) can just be treated as normal files for this.
  // Each open/close of the same file will have a separate file in the FS.
  // Each open/close is identified by the tick on which it was opened.
  // For example, for process 2 on tick 1234:
  //
  //   /data/myfile -> <demo_base>/FS2/.data.myfile1234
  //
  // File operations are inter-process, so need to be ordered across processes
  // just like with forking.
  // Tsan's fd stuff is borrowed to store the fds for reads and writes.
  void FileCreate(const char *file, int *fd_replay, int *fd_record);
  void FileRead(int *fd_replay, int *fd_record, char *buffer);


  ////////////////////////////////////////
  // Other utilities.
  ////////////////////////////////////////

  // If the scheduler chooses a thread that does not do atomic operations, or is
  // waiting for some other thread that is blocked by the scheduler, then the
  // program will deadlock.
  // This will force the scheduler to choose another thread. If a demo is being
  // recorded then the last scheduler choice will be erased. If this is a demo
  // playback then this should be a noop.
  // Must ONLY be called by the background thread.
  void Reschedule();

  // For demo playback and recording.
  // Helps verify that demo playback is in sync.
  // Easy access to demo recording.
  // Only call if this is the active thread.
  enum EventType { END = 0,     SCHEDULE = 1, READ = 2, COND_SIGNAL = 3,
                   PROCESS = 4, FILE = 5,     MMAP = 6 };
  u64 RandomNext(ThreadState *thr, EventType event_type);

  // For ease of functions that use the mutex and Wait().
  friend struct ScopedScheduler;

 private:
  // When performing a blocking call, the thread should disable itself.
  void Enable(int tid);
  void Disable(int tid);


  ////////////////////////////////////////
  // Demo playback.
  ////////////////////////////////////////

  struct DemoPlay {
    bool play_demo_;        // In demo playback.
    u64 demo_tick_;         // Tick for next demo input.
    EventType event_type_;  // Type of next demo input. END if demo is finished.
    u64 event_param_;       // Param if applicable (e.g. atomic::load rf).
    u64 rnd_skip_;          // Skip this many calls to the RNG.
    char *demo_contents_;   // Raw demo contents.
  };
  struct DemoPlay demo_play_;

  // Initialise demo playback.
  void DemoPlayInitialise();
  // Parse next event from file during demo playback.
  void DemoPlayNext();
  // Is demo playback active.
  bool DemoPlayActive();   // Enabled and not at end.
  bool DemoPlayEnabled();  // Enabled, maybe at end.
  // Assert demo state.
  void DemoPlayCheck(u64 demo_tick, EventType event_type, u64 param1, u64 param2);
  bool DemoPlayExpectParam1(u64 param1);
  bool DemoPlayExpectParam2(u64 param2);


  ////////////////////////////////////////
  // Demo record.
  ////////////////////////////////////////

  struct DemoRecord {
    fd_t record_fd_;
    u64 demo_tick_;
    EventType event_type_;
    u64 event_param_;
    u64 rnd_skip_;
  };
  struct DemoRecord demo_record_;

  // Initialise demo recording.
  void DemoRecordInitialise();
  // Record an event to the demo record file.
  // Ususally you do not need to store any playback info as having the same
  // random seeds would create the same sequence of events. There are some cases
  // that require it, such as calls to Reschedule() or external influence.
  void DemoRecordNext(u64 tick, EventType type, u64 param, u64 rnd_skip);
  // Is demo recording enabled.
  bool DemoRecordEnabled();
  // Override previous tick. Requires type to be the same.
  // If there is not entry for the tick, a new one is created.
  // rnd_skip is added to the entry if it exists.
  void DemoRecordOverride(u64 tick, EventType type, u64 param, u64 rnd_skip);


  ////////////////////////////////////////
  // Scheduler state.
  ////////////////////////////////////////

  // Represents a deterministic time point for the program.
  // This changes on each tick, and should not differ when replaying.
  u64 tick_;

  // Serves two purposes: check for concurrent accesses and synchronisation.
  // There should be no contention for this mutex besides Reschedule().
  Mutex mtx;

  // Condition variables each thread needs to wait on before proceeding.
  // We don't want to use mutexes, as different thread will block and notify.
  // We want a compacted array of active threads so we can easily see which
  // threads are used and easily select one at random.
  static const int kNumThreads = 80;
  static const int kInactive = 0;
  static const int kActive = 1;

  // cond_vars_idx_[rnd(0, last_free_idx_)] gives an active tid.
  // cond_vars_idx_inv_[tid] with active tid gives its position cond_vars_idx_.
  // All active tids at any point are packed in cond_vars_idx_.
  atomic_uintptr_t cond_vars_[kNumThreads];
  int cond_vars_idx_[kNumThreads];
  int cond_vars_idx_inv_[kNumThreads];
  int last_free_idx_;

  enum Status { FINISHED = 0, DISABLED = 1, CONDITIONAL = 2, RUNNING = 3 };
  Status thread_status_[kNumThreads];
  int wait_tid_[kNumThreads];                   // For thread join
  atomic_uintptr_t *thread_cond_[kNumThreads];  // For conditionals

  // For non-replay, check when we need to reschedule.
  u64 reschedule_tick_;

  // Shared memory for inter-process ordering.
  u64 pid_;
  struct ShmProcess *shm_process_;
};

}  // namespace __tsan

#endif  // TSAN_SCHEDULE_H_
