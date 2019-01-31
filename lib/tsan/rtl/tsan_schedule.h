// Scheduler for tsan11.

#ifndef TSAN_SCHEDULE_H_
#define TSAN_SCHEDULE_H_

#include "sanitizer_common/sanitizer_atomic.h"
#include "tsan_defs.h"
#include "tsan_mutex.h"

namespace __tsan {

// Controls scheduling, waking of threads and history.
class Scheduler {
 public:
  // For ease of functions that use the mutex and Wait().
  friend struct ScopedScheduler;

  Scheduler();
  ~Scheduler();

  // Performed here instead of constructor, as flags need to be initialised.
  void Initialise();


  ////////////////////////////////////////
  // Core ordering functions.
  // Dynamically bound on startup according to the chosen strategy.
  ////////////////////////////////////////

 private:
  // Dynamic bindings for the ordering functions.
  void (Scheduler::*WaitFunc)(ThreadState *thr);
  void (Scheduler::*TickFunc)(ThreadState *thr);
  void (Scheduler::*EnableFunc)(int tid);
  void (Scheduler::*DisableFunc)(int tid);
  void (Scheduler::*RescheduleFunc)();
  void (Scheduler::*SignalWakeFunc)(ThreadState *thr);

 public:
  // Block this thread until the scheduler allows it to run.
  // Call immediately before a visible operation.
  inline void Wait(ThreadState *thr) { (this->*WaitFunc)(thr); }

  // Uses the chosen scheduling strategy to pick the next thread to activate.
  // Call immediately after a visible operation.
  inline void Tick(ThreadState *thr) { (this->*TickFunc)(thr); }

  // Add and remove thread tid from the list of schedulable threads.
  // These are not asyn safe, so should only be called in a critical section, or
  // by Reschedule() or SignalWake().
  inline void Enable(int tid) { (this->*EnableFunc)(tid); }
  inline void Disable(int tid) { (this->*DisableFunc)(tid); }

  // If the scheduler chooses a thread that does not do atomic operations, or is
  // waiting for some other thread that is blocked by the scheduler, then the
  // program may deadlock or become unresposive.
  // This will force the scheduler to choose another thread.
  // If this is a demo playback, then all the reschedules after the last Tick()
  // and before the next Wait() will float to before the last Tick(), and this
  // function will do nothing.
  // Must only be called by the background thread.
  inline void Reschedule() { (this->*RescheduleFunc)(); }

  // If a signal is received and the thread is disabled, in must be reenabled so
  // it can enter the signal handler.
  // If this is a replay, this function does nothing, like Reschedule().
  inline void SignalWake(ThreadState *thr) { (this->*SignalWakeFunc)(thr); }


  ////////////////////////////////////////
  // Event specific interface functions.
  // Called from outside on particular cases that require ordering.
  ////////////////////////////////////////

  // Thread update functions.
  // Only necessary for thread creation, finishing and joining.
  void ThreadNew(ThreadState *thr, int tid);
  void ThreadDelete(ThreadState *thr);
  void ThreadJoin(ThreadState *thr, int join_tid);

  // Condition variables.
  // Conditional wait is split into two separate critical sections. The wait
  // followed by a mutex lock when signalled.
  //
  // A thread doing a wait with timeout is not disabled, but can still eat up a
  // signal provided it has not done anything that happens after the signal.
  void CondWait(ThreadState *thr, void *c, bool timed);
  void CondSignal(ThreadState *thr, void *c);
  void CondBroadcast(ThreadState *thr, void *c);

  // Mutex lock and unlock. Mutex lock fail will block the thread as it will
  // just waste time. Unlock will wake up one thread that was blocked.
  // Successful mutex lock does not require action.
  void MutexLockFail(ThreadState *thr, void *m);
  void MutexUnlock(ThreadState *thr, void *m);

  // Forking off processes.
  // For demo record/replay, a simple high level scheduler is used to ensure
  // they are created in the same order and that they get their own demo file,
  // that is assigned correctly when replying.
  // Each process created has its own id, that is the same as the demo file it
  // will read from. This will be acquired from a section of shared memory.
  // Currently disabled.
  u64 ForkBefore(ThreadState *thr);
  void ForkAfterParent(ThreadState *thr);
  void ForkAfterChild(ThreadState *thr, u64 id);

  // Only asynchronous signals are handled, as these can be sent from other
  // threads or processes at any time. Synchronous signals (r.g. SIGSEGV,
  // SIGPIPE), are usually deteministically raised by the same thread.
  //
  // A signal is only received when the thread calls ProcessPendingSignals or if
  // the thread is in a blocking call such as pthread_join. Intercepted libc and
  // system calls are what lead to ProcessPendingSignals being called.
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
  // TODO this is broken.
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
  bool SyscallIsInputFd(const char *addr, uptr addrlen);

  void SyscallAccept(int *ret, int sockfd, void *addr, unsigned *addrlen, unsigned addrlen_pre);
  void SyscallBind(int *ret, int fd, void *addr, uptr addrlen);
  void SyscallClock_gettime(int *ret, void *tp);
  void SyscallClose(int *ret, int fd, void *close);
  void SyscallConnect(int *ret, int sockfd, void *addr, uptr addrlen);
  void SyscallEpoll_wait(int *ret, int epfd, void *events, int maxevents, int timeout);  // Inactive
  void SyscallGetsockname(int *ret, int sockfd, void *addr, unsigned *addrlen);
  void SyscallGettimeofday(int *ret, void *tv, void *tz);  // Inactive
  void SyscallIoctl(int *ret, int fd, unsigned long request, void *arg);  // Inactive
  void SyscallPipe(int *ret, int pipefd[2]);
  void SyscallPoll(int *ret, void *fds, unsigned nfds, int timeout);
  void SyscallRead(sptr *ret, int fd, void *buf, uptr count, void *read);
  void SyscallRecv(sptr *ret, int sockfd, void *buf, uptr len, int flags);
  void SyscallRecvfrom(sptr *ret, int sockfd, void *buf, uptr len, int flags, void *src_addr, int *addrlen, uptr addrlen_pre);
  void SyscallRecvmsg(sptr *ret, int sockfd, void *msghdr, int flags, void *recvmsg);
  void SyscallSendmsg(sptr *ret, int sockfd, void *msghdr, int flags);
  void SyscallSendto(sptr *ret, int sockfd, void *buf, uptr len, int flags, void *dest_addr, int addrlen);
  void SyscallSelect(int *ret, int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout, void *select);
  void SyscallWrite(sptr *ret, int fd, void *buf, uptr count, void *write);
  void SyscallWritev(sptr *ret, int fd, void *iov, int iovcnt);

  // Does not do anything.
  void FileCreate(const char *file, int *fd_replay, int *fd_record);
  //void FileRead(int *fd_replay, int *fd_record, char *buffer);


  ////////////////////////////////////////
  // PRNG utilities.
  ////////////////////////////////////////

  // Get next number in a deterministic PRNG.
  // To preserve the deterministic replayability this must only be called inside
  // the Wait and Tick of ordered instructions.
  static u64 RandomNumber();

  // Interface for RandomNumber() that is preferrable to calling it directly.
  // Handles some cases safely that may break record and replay.
  u64 RandomNext(ThreadState *thr);


  ////////////////////////////////////////
  // Annotations.
  ////////////////////////////////////////

  // The next function entered runs free from any scheduling.
  // Wait() will be called, with the following Tick() occuring after it returns.
  // As the whole function is a critical section, other threads will be blocked.
  void AnnotateExcludeEnter();
  void AnnotateExcludeExit();
  static void AEx();
  static void ARe();

  // For system calls. Check if this is demo playback to avoid blocking.
  bool IsDemoPlayback();


  // Only a static number of threads is supported due to static sized arrays.
  static const int kNumThreads = 80;

  // For demo event record and replay. Types of events.
  enum EventType { END = 0, RESCHEDULE = 1, SIG_WAKEUP = 2 };
 private:
  ////////////////////////////////////////
  // Dynamic dispatch (for strategy).
  ////////////////////////////////////////

  // When making a scheduling strategy, consider the following:
  // - Does it work with the event record and replay.
  // - Does it work with time slicing.
  // - Handle signals properly?

  // No scheduling.
  //struct StrategyNone;
  void StrategyNoneInitialise();
  void StrategyNoneWait(ThreadState *thr);
  void StrategyNoneTick(ThreadState *thr);
  void StrategyNoneEnable(int tid);
  void StrategyNoneDisable(int tid);
  void StrategyNoneReschedule();
  void StrategyNoneSignalWake(ThreadState *thr);

  // Random scheduling.
  //struct StrategyRandom;
  void StrategyRandomInitialise();
  void StrategyRandomWait(ThreadState *thr);
  void StrategyRandomTick(ThreadState *thr);
  void StrategyRandomEnable(int tid);
  void StrategyRandomDisable(int tid);
  void StrategyRandomReschedule();
  void StrategyRandomSignalWake(ThreadState *thr);

  // Queue scheduling.
  //struct StrategyQueue;
  void StrategyQueueInitialise();
  void StrategyQueueWait(ThreadState *thr);
  void StrategyQueueTick(ThreadState *thr);
  void StrategyQueueEnable(int tid);
  void StrategyQueueDisable(int tid);
  void StrategyQueueReschedule();
  void StrategyQueueSignalWake(ThreadState *thr);


  ////////////////////////////////////////
  // Other internal utilities.
  ////////////////////////////////////////

  // Print the frame at the top of the user stack, before entering sanitizer.
  void PrintUserSanitizerStackBoundary();

  // The normal way a thread blocks itself until a condition holds is a
  // compare_exchange loop with proc_yield(20) inside. This takes up CPU time
  // from active threads, and delays the scheduler if the thread is signalled
  // just after a proc_yield call.
  // These provide block/signal where the thread stays asleep until signalled,
  // and will wake up quickly.
  // Uses SIGUSR2 and sigwait, so SIGUSR2 cannot be used by the user.
  void BlockWait(int tid, atomic_uintptr_t *p, u64 exp, u64 des,
      bool allow_signal_arrival);
  void BlockSignal(int tid);


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
    u64 signal_tick_[kNumThreads];    // Next signal tick.
    int signal_num_[kNumThreads];     // Next signal numbers.
    char *signal_contents_;           // Signal replay file.
    // Syscall replaying.
    //int syscall_fd_map_[128];  // Map replay fds to real fds.
    char *syscall_contents_;   // Syscall replay file.
  };
  struct DemoPlay demo_play_;

  // Initialise demo playback.
  void DemoPlayInitialise();
  // Parse next event from file during demo playback.
  void DemoPlayNext();
  void DemoPlayPeekNext();
  // Is demo playback active.
  bool DemoPlayActive();   // Enabled and not at end.
  bool DemoPlayEnabled();  // Enabled, maybe at end.
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
    int signal_num_[kNumThreads];       // Signal nums of first signal received.
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
  // Changes on each Tick(), should not differ when replaying.
  u64 tick_;

  // For mofifying scheduler state. Not needed for Wait(), or if the thread only
  // modifies array at its own index.
  Mutex mtx;

  // For any effect that may need to change which thread is running or change
  // the state outside of Wait() and Tick() (e.g. Reschedule()).
  int active_tid_;

  // For time slices.
  int slice_length = 1;
  int slice_;

  // Debug info
  bool print_trace = false;

  // Info for blocked threads.
  enum Status { FINISHED = 0, DISABLED = 1, CONDITIONAL = 2, RUNNING = 3 };
  Status thread_status_[kNumThreads];
  int wait_tid_[kNumThreads];                   // For thread join
  atomic_uintptr_t *thread_cond_[kNumThreads];  // For conditionals
  atomic_uintptr_t *thread_mtx_[kNumThreads];   // For mutex lock TODO merge with cond.

  // For signals, each thread has an epoch for determinism.
  u64 signal_tick_[kNumThreads];
  int signal_context_[kNumThreads];

  // For syscalls, some fds represent input. These will be recorded/replayed.
  // This is owned by both the record and replay state.
  static const int kMaxFd = 128;
  int input_fd_[kMaxFd];
  int fd_map_[kMaxFd];   // demo replay fd to actual fd (for select).
  int pipe_fd_[kMaxFd];  // Pipes are recorded in poll and ordered in read/write.

  // For excluding specific functions from the scheduler.
  int exclude_point_[kNumThreads];

  // For the blocking wait and signal.
  int pids_[kNumThreads];
  atomic_uintptr_t block_gate_[kNumThreads];
};

}  // namespace __tsan

extern "C" void __tsan__Scheduler__ARe();
extern "C" void __tsan__Scheduler__AEx();

#endif  // TSAN_SCHEDULE_H_
