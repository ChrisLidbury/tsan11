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
  // Usually only necessary for thread creation, finishing and joining.
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

  // Signals have some very subtle behaviours that need handling. In particular,
  // when they can be received and ensuring they are replayed precisely.
  //
  // Only asynchronous signals are handled, as these can be sent from other
  // threads or processes at any time. Synchronous signals (r.g. SIGSEGV,
  // SIGPIPE), are usually deteministically raised by the same thread.
  //
  // A signal is only received when the thread calls ProcessPendingSignals or if
  // the thread is in a blocking call such as pthread_join. Intercepted libc and
  // system calls are what lead to ProcessPendingSignals being called.
  //
  // When replaying, the signal should arrive at the same time, not just at the
  // same tick. ProcessPendingSignals and blocking calls can occur many times
  // between each tick, so a separate, thread-local epoch will be used to keep
  // track of the number of times a signal could have potentially been received,
  // and raise the signal on the same signal tick.
  //
  // Upon replay, all other signals are ignored. The way a scheduled signal is
  // received depends on the context. If it is through ProcessPendingSignals
  // then the thread can check and raise the signal itself. If it is in a
  // blocking call the background thread must check and use kill on the thread. (TODO not true)
  //
  // Receiving a signal still uses the wait'n'tick, but we can tick as soon as
  // wait returns, instead of at the end of the signal handler. This is because
  // it is just a function call, and the contents of the signal handler may
  // involve visible operations that need scheduling.
  bool SignalReceive(ThreadState *thr, int signum, bool blocking);
  void SignalPending(ThreadState *thr);  // Called by ProcessPendingSignals.

  // System call scheduling and record/replay.
  //
  // Certain system calls that interact with the OS and potentially other
  // processes are handled by these set of functions. Most behave in specific
  // ways and need certain information saved, and so have their own funcitons.
  //
  // Some of them will need to be ordered, and thus do the wait'n'tick. Each
  // will also need their own syscall epoch to ensure that what we replay lines
  // up with when it was recorded.
  void SyscallConnect(int *ret, int sockfd, void *addr, uptr addrlen);
  void SyscallIoctl(int *ret, int fd, unsigned long request, void *arg);
  void SyscallPoll(int *ret, void *fds, unsigned nfds, int timeout);
  void SyscallRecv(sptr *ret, int sockfd, void *buf, uptr len, int flags);
  void SyscallRecvfrom(sptr *ret, int sockfd, void *buf, uptr len, int flags,
                       void *src_addr, int *addrlen, uptr addrlen_pre);
  void SyscallRecvmsg(sptr *ret, int sockfd, void *msghdr, int flags);
  //void SyscallSocket(int *ret, int domain, int type, int protocol);
  // Map the fake fd used when replaying with the actual fd. This is so that the
  // REAL syscall can use the actual fd, but the rest of the program uses the
  // same fd as that when the demo was recorded.
  //int SyscallFdMap(int fd);

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
                   PROCESS = 4, FILE = 5,     MMAP = 6, SIGNAL = 7 };
  u64 RandomNext(ThreadState *thr, EventType event_type);

  // For ease of functions that use the mutex and Wait().
  friend struct ScopedScheduler;

 private:
  // When performing a blocking call, the thread should disable itself.
  void Enable(int tid);
  void Disable(int tid);


  // Only a static number of threads is supported due to static sized arrays.
  static const int kNumThreads = 80;


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
    // Signal replaying.
    u64 signal_tick_[kNumThreads];  // Next signal tick.
    u32 signal_num_[kNumThreads];   // Next signal numbers.
    char *signal_contents_;         // Signal replay file.
    // Syscall replaying.
    //int syscall_fd_map_[128];  // Map replay fds to real fds.
    char *syscall_contents_;   // Syscall replay file.
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
  void DemoPlayCheck(
      u64 demo_tick, EventType event_type, u64 param1, u64 param2);
  bool DemoPlayExpectParam1(u64 param1);
  bool DemoPlayExpectParam2(u64 param2);
  // Signal replay.
  void DemoPlaySignalNext(int tid);
  // Syscall replay.
  void DemoPlaySyscallNext(
      const char *func, uptr param_count, void *param[], uptr param_size[]);
  void DemoPlaySyscallNextCheck();


  ////////////////////////////////////////
  // Demo record.
  ////////////////////////////////////////

  struct DemoRecord {
    fd_t record_fd_;
    u64 demo_tick_;
    EventType event_type_;
    u64 event_param_;
    u64 rnd_skip_;
    // Signal recording.
    // When a thread replays a signal, it must immediately know the tick of the
    // next, but it will not know until it occurs. The file offset should
    // therefore be saved and written to when the next signal is recorded.
    int signal_file_pos_[kNumThreads];  // Signal file position for next signal.
    u64 signal_tick_[kNumThreads];      // Signal tick of first signal received.
    u32 signal_num_[kNumThreads];       // Signal nums of first signal received.
    fd_t signal_fd_;
    // Syscall recording.
    // Each syscall requires different parameters to be stored.
    fd_t syscall_fd_;
  };
  struct DemoRecord demo_record_;

  // Initialise/Finalise demo recording.
  void DemoRecordInitialise();
  void DemoRecordFinalise();
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
  // For a signal, the signal_tick should be stored in its own file, and the
  // first tick needs to be stored in the signal file header.
  void DemoRecordSignalNext(int tid, u64 signal_tick, int signum);
  void DemoRecordSignalLine(char *buf, int tid, u64 signal_tick, int signum);
  // Syscall store call.
  void DemoRecordSyscallNext(
      const char *func, uptr param_count, void *param[], uptr param_size[]);


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
  //static const int kNumThreads = 80;
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

  // For signals, each thread has an epoch for determinism.
  u64 signal_tick_[kNumThreads];

  // For non-replay, check when we need to reschedule.
  u64 reschedule_tick_;

  // Shared memory for inter-process ordering.
  u64 pid_;
  struct ShmProcess *shm_process_;
};

}  // namespace __tsan

#endif  // TSAN_SCHEDULE_H_
