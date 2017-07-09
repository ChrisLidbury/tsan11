#include "tsan_schedule.h"

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_platform_limits_posix.h"
#include "sanitizer_common/sanitizer_symbolizer.h"
//#include "sanitizer_common/sanitizer_posix.h"  // For internal_lseek
#include "tsan_mutex.h"
#include "tsan_rtl.h"

int tsanstart = 0;

extern "C" int raise(int sig);  // For signal replay.
//#include <cerrno>               // For syscall record/replay.
extern "C" int *__errno_location();

// fd set macros for syscall select.
#define FD_ZERO(fds) {u64 *fds_ = (u64 *)fds; fds_[0] = 0; fds_[1] = 0;}
#define FD_CLR(fd, fds) (((u64 *)fds)[fd / 64] &= ~((u64)1 << (fd % 64)))
#define FD_SET(fd, fds) (((u64 *)fds)[fd / 64] |= ((u64)1 << (fd % 64)))
#define FD_ISSET(fd, fds) ((((u64 *)fds)[fd / 64] & ((u64)1 << (fd % 64))) != 0)

// Only for POSIX.
namespace __sanitizer {
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEET_END 2
uptr internal_lseek(fd_t fd, OFF_T offset, int whence);
}  // namespace __sanitizer

namespace __tsan {
namespace {

// Fetch the value in the tsc register (x86).
// Can be used as a random value (for the lower bits).
static inline u64 rdtsc() {
  u64 ret;
  asm volatile ("rdtsc; "          // read of tsc
                "shl $32,%%rdx; "  // shift higher 32 bits stored in rdx up
                "or %%rdx,%%rax"   // and or onto rax
                : "=a"(ret)        // output to tsc
                :
                : "%rcx", "%rdx", "memory");  // rcx and rdx are clobbered
                                              // memory to prevent reordering
  return ret;
}

// Very fast PRNG. Must be seeded using the rdtsc unless a seed is provided.
// Borrowed from wiki.
u64 s[2];
u64 xorshift128plus() {
  u64 x = s[0];
  const u64 y = s[1];
  s[0] = y;
  x ^= x << 23;  // a
  s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);  // b, c
  return s[1] + y;
}

}  // namespace

// Shared memory for inter-process ordering.
struct ShmProcess {
  ShmProcess()
      : tick_(1), mtx_(MutexTypeShmProcess, StatMtxTotal),
        replay_contents_(0), replay_next_(0), record_fd_(kInvalidFd) {
  }
  u64 tick_;
  Mutex mtx_;
  char *replay_contents_;  // Contents are memory mapped.
  u64 replay_next_;        // Last in the replay.
  fd_t record_fd_;
};
// We cannot just include the required headers, so the bare essentials are
// forward declared (shmget, shmctl, shmat).
#define IPC_RMID	0
#define IPC_CREAT	01000
extern "C" int shmctl(int shmid, int cmd, void *buf);
extern "C" int shmget(int key, unsigned size, int shmflg);
extern "C" void *shmat(int shmid, const void *shmaddr, int shmflg);

// As most scheduler functions go: Wait -> Lock -> f -> Unlock -> Tick.
struct ScopedScheduler {
  ScopedScheduler(Scheduler *scheduler, ThreadState *thr)
      : scheduler_(scheduler), thr_(thr) {
    scheduler_->Wait(thr_);
    scheduler_->mtx.Lock();
  }
  ~ScopedScheduler() {
    scheduler_->mtx.Unlock();
    scheduler_->Tick(thr_);
  }
  Scheduler *scheduler_;
  ThreadState *thr_;
};

// Start of Scheduler stuff.
Scheduler::Scheduler()
    : tick_(0), mtx(MutexTypeSchedule, StatMtxTotal), last_free_idx_(0),
      reschedule_tick_(0), pid_(0) {
  internal_memset(cond_vars_, kInactive, sizeof(cond_vars_));
  internal_memset(thread_status_, FINISHED, sizeof(thread_status_));
  internal_memset(wait_tid_, -1, sizeof(wait_tid_));
  internal_memset(thread_cond_, 0, sizeof(thread_cond_));
  internal_memset(thread_mtx_, 0, sizeof(thread_mtx_));
  internal_memset(exclude_point_, 0, sizeof(exclude_point_));
}

Scheduler::~Scheduler() {
  DemoRecordFinalise();
}

// Assume this is the only scheduler.
void Scheduler::Initialise() {
  // Setup start thread.
  // This thread will still call ThreadNew, so do not adjust last_free_idx_.
  atomic_store(&cond_vars_[0], kActive, memory_order_relaxed);
  // Assumes ownership of PRNG buffer. Can make a member if multiple schedulers.
  s[0] = rdtsc();
  s[1] = rdtsc();

  // Set up demo playback.
  DemoPlayInitialise();
  DemoRecordInitialise();

  // Shared memory init.
  /*static const*/ int key = ('t' << 24) | ('s' << 16) | ('a' << 8) | 'n';
  key ^= (int)(internal_getpid() & (int)-1);
  int id = shmget(key, sizeof(ShmProcess), 0777);
  if (id != -1) {
    int value = shmctl(id, IPC_RMID, 0);
    CHECK(!value && "Could not kill old shared memory.");
  }
  id = shmget(key, sizeof(ShmProcess), IPC_CREAT | 0777);
  CHECK((id != -1) && "Could not create shared memory.");
  shm_process_ = new(shmat(id, 0, 0)) ShmProcess();
  if (DemoPlayEnabled()) {
    // Memory map replay contents. Must have an initial entry 0.
    char buf[128];
    internal_snprintf(buf, 128, "%s/PROCESS", flags()->play_demo);
    uptr size;
    shm_process_->replay_contents_ = (char *)MapFileToMemory(buf, &size);
    shm_process_->replay_next_ = *shm_process_->replay_contents_ == '\0' ? -1 :
        internal_simple_strtoll(shm_process_->replay_contents_,
                                &shm_process_->replay_contents_, 10);
    CHECK(shm_process_->replay_next_ == 0);
    shm_process_->replay_next_ = *shm_process_->replay_contents_ == '\0' ? -1 :
        internal_simple_strtoll(shm_process_->replay_contents_,
                                &shm_process_->replay_contents_, 10);
  }
  if (DemoRecordEnabled()) {
    char buf[128];
    internal_snprintf(buf, 128, "%s/PROCESS", flags()->record_demo);
    shm_process_->record_fd_ = OpenFile(buf, WrOnly);
    WriteToFile(shm_process_->record_fd_, "0\n", internal_strlen("0\n"));
  }
}


////////////////////////////////////////
// Core ordering functions.
////////////////////////////////////////

void Scheduler::Wait(ThreadState *thr) {
  uptr cmp = kActive;
  while (!atomic_compare_exchange_strong(
      &cond_vars_[thr->tid], &cmp, kCritical, memory_order_relaxed)) {
    CHECK(cmp == kInactive);
    cmp = kActive;
    // Racy
    //pri_[thr->tid] = kMaxPri;
    proc_yield(20);
  }
}

void Scheduler::Tick(ThreadState *thr) {
  mtx.Lock();
  uptr cmp = kCritical;
  bool is_critical = atomic_compare_exchange_strong(
      &cond_vars_[thr->tid], &cmp, kInactive, memory_order_relaxed);
  CHECK(is_critical);
  // If annotated out, immedaitely reenable this thread.
  if (exclude_point_[thr->tid] == 1 && thread_status_[thr->tid] != DISABLED) {
    atomic_store(&cond_vars_[thr->tid], kActive, memory_order_relaxed);
    mtx.Unlock();
    return;
  }
  if (pri_[thr->tid] > kMaxPri) {
    --pri_[thr->tid];
    //pri_[thr->tid] = kMaxPri;
  }
  {
  Printf("%d - %d - ", thr->tid, tick_);
  PrintUserSanitizerStackBoundary();
  Printf("\n");
  }
  // Now to find the next tid to activate.
  int next_tid;
  u64 rnd = RandomNext(thr, SCHEDULE);
  if (rnd == (u64)-1) {
    for (u64 demo_skip = demo_play_.rnd_skip_; demo_skip > 0; --demo_skip) {
      int skip_tid = Schedule(RandomNumber());
      if (pri_[skip_tid] < kMinPri) {
        ++pri_[skip_tid];
      }
    }
    RandomNumber();
    next_tid = demo_play_.event_param_;
  } else {
    next_tid = Schedule(rnd);
  }
  // Activate chosen next tid.
  CHECK(thread_status_[next_tid] == RUNNING ||
      (next_tid == 0 && last_free_idx_ == 0));
  atomic_store(&cond_vars_[next_tid], kActive, memory_order_relaxed);
  active_tid_ = next_tid;
  mtx.Unlock();
}

void Scheduler::Reschedule() {
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
  CHECK(thread_status_[next_tid] == RUNNING);
  atomic_store(&cond_vars_[next_tid], kActive, memory_order_relaxed);
  active_tid_ = next_tid;
  DemoRecordOverride(tick_ - 1, SCHEDULE, next_tid, 1);
  mtx.Unlock();
}

int Scheduler::Schedule(u64 rnd) {
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


////////////////////////////////////////
// Event specific interface functions.
////////////////////////////////////////

void Scheduler::ThreadNew(ThreadState *thr, int tid) {
  ScopedScheduler scoped(this, thr);
  Enable(tid);
  if (thr->tid != tid) {
    atomic_store(&cond_vars_[tid], kInactive, memory_order_relaxed);
  }
}

void Scheduler::ThreadDelete(ThreadState *thr) {
  ScopedScheduler scoped(this, thr);
  Disable(thr->tid);
  thread_status_[thr->tid] = FINISHED;
  int ptid = thr->tctx->parent_tid;
  // Wakes up parent thread if it is waiting for this thread to finish.
  if (thread_status_[ptid] != RUNNING && wait_tid_[ptid] == thr->tid) {
    CHECK(thread_status_[ptid] != FINISHED);
    Enable(ptid);
    wait_tid_[ptid] = -1;
  }
}

void Scheduler::ThreadJoin(ThreadState *thr, int join_tid) {
  ScopedScheduler scoped(this, thr);
  // Disables itself if the joining thread is not finished.
  if (thread_status_[join_tid] != FINISHED) {
    Disable(thr->tid);
    wait_tid_[thr->tid] = join_tid;
  }
}

void Scheduler::CondWait(ThreadState *thr, void *c, bool timed) {
  mtx.Lock();
  if (!timed) {
    Disable(thr->tid);
  }
  // Do not disable if timed wait, but can still eat a signal.
  thread_cond_[thr->tid] = (atomic_uintptr_t*)c;
  mtx.Unlock();
}

void Scheduler::CondSignal(ThreadState *thr, void *c) {
  // TODO A timedwait should NOT eat a signal if some operation in the
  // timedwaiting thread that happens after the timedwait happens before this
  // signal.
  // TODO Come up with a way of selecting a thread in O(1) time, using arrays.
  // Currently uses an expensive linear search that goes through all threads.
  ScopedScheduler scoped(this, thr);
  int cond_tids[kNumThreads];
  int count = 0;
  for (int i = 0; i < kNumThreads; ++i) {
    if (thread_cond_[i] == (atomic_uintptr_t*)c) {
      cond_tids[count++] = i;
    }
  }
  if (count == 0) {
    return;
  }
  int tid_signal = cond_tids[RandomNext(thr, COND_SIGNAL) % count];
  if (thread_status_[tid_signal] == DISABLED) {
    Enable(tid_signal);
  }
  thread_cond_[tid_signal] = 0;
}

void Scheduler::CondBroadcast(ThreadState *thr, void *c) {
  ScopedScheduler scoped(this, thr);
  for (int i = 0; i < kNumThreads; ++i) {
    if (thread_cond_[i] == (atomic_uintptr_t*)c) {
      if (thread_status_[i] == DISABLED) {
        Enable(i);
      }
      thread_cond_[i] = 0;
    }
  }
}

void Scheduler::MutexLockFail(ThreadState *thr, void *m) {
  mtx.Lock();
  Disable(thr->tid);
  thread_mtx_[thr->tid] = (atomic_uintptr_t*)m;
  mtx.Unlock();
}

void Scheduler::MutexUnlock(ThreadState *thr, void *m) {
  mtx.Lock();
  int mtx_tids[kNumThreads];
  int count = 0;
  for (int i = 0; i < kNumThreads; ++i) {
    if (thread_mtx_[i] == (atomic_uintptr_t*)m) {
      mtx_tids[count++] = i;
    }
  }
  if (count == 0) {
    mtx.Unlock();
    return;
  }
  int tid_signal = mtx_tids[RandomNext(thr, COND_SIGNAL) % count];
  if (thread_status_[tid_signal] == DISABLED) {
    Enable(tid_signal);
  }
  thread_mtx_[tid_signal] = 0;
  mtx.Unlock();
}

// Check if the next forked process is done by this thread.
// Check if shm specifies this process
u64 Scheduler::ForkBefore(ThreadState *thr) {
  mtx.Lock();
  DemoPlayCheck(tick_, PROCESS, (u64)thr->tid, (u64)-1);
  u64 new_id;
  for (;;) {
    shm_process_->mtx_.Lock();
    new_id = shm_process_->tick_;
    if (DemoPlayExpectParam2(new_id) && (!DemoPlayEnabled() ||
        (shm_process_->replay_next_ == (u64)-1 ||
         shm_process_->replay_next_ == pid_))) {
      break;
    }
    shm_process_->mtx_.Unlock();
    proc_yield(20);
  }
  DemoPlayNext();
  if (DemoPlayEnabled()) {
    shm_process_->replay_next_ = *shm_process_->replay_contents_ == '\0' ? -1 :
        internal_simple_strtoll(shm_process_->replay_contents_,
                                &shm_process_->replay_contents_, 10);
  }
  DemoRecordNext(tick_, PROCESS, thr->tid, new_id);
  if (DemoRecordEnabled()) {
    char buf[32];
    internal_snprintf(buf, 32, "%llu\n", pid_);
    WriteToFile(shm_process_->record_fd_, buf, internal_strlen(buf));
  }
  ++shm_process_->tick_;
  shm_process_->mtx_.Unlock();
  ++tick_;
  mtx.Unlock();
  return new_id;
}

void Scheduler::ForkAfterParent(ThreadState *thr) {
}

void Scheduler::ForkAfterChild(ThreadState *thr, u64 id) {
  pid_ = id;
  s[0] = rdtsc();
  s[1] = rdtsc();
  DemoPlayInitialise();
  CloseFile(demo_record_.record_fd_);
  DemoRecordInitialise();
}

bool Scheduler::SignalReceive(ThreadState *thr, int signum, bool blocking) {
  mtx.Lock();
  if (DemoPlayActive() &&
      demo_play_.signal_tick_[thr->tid] != signal_tick_[thr->tid]) {
    mtx.Unlock();
    return false;
  }
  bool reenable = thread_status_[thr->tid] == DISABLED;
  if (reenable) {
    Enable(thr->tid);  // TODO on blocking in replay, thread needs to be woken at correct time.
  }
  mtx.Unlock();  // TODO other thread may have reenabled.
  Wait(thr);
  mtx.Lock();
  if (reenable) {
    Disable(thr->tid);
  }
  DemoRecordSignalNext(thr->tid, signal_tick_[thr->tid], signum);
  if (blocking) {
    // The ordering of signals in blocking calls is important.
    // TODO Disable signal handling when here.
    ++signal_tick_[thr->tid];
  }
  mtx.Unlock();
  Tick(thr);
  return true;
}

void Scheduler::SignalPending(ThreadState *thr) {
  ++signal_tick_[thr->tid];
  if (DemoPlayActive() &&
      demo_play_.signal_tick_[thr->tid] == signal_tick_[thr->tid]) {
    //Wait(thr);
    for (int signal = 1, signals = demo_play_.signal_num_[thr->tid];
         signals > 0;
         ++signal, signals >>= 1) {
      if (signals & 1) {
        raise(signal);
      }
    }
  }
}

bool Scheduler::SyscallIsInputFd(const char *addr, uptr addrlen) {
  static const char *const kInputAddrs[3] =
      {"/tmp/.X11-unix/X0", "/tmp/dbus-", "/run/user/" };
  static const uptr kInputAddrLens[3] = {17, 10, 10};
  for (unsigned idx = 0; idx < 3; ++idx) {
    uptr len = addrlen > kInputAddrLens[idx] ? kInputAddrLens[idx] : addrlen;
    if (internal_strncmp(kInputAddrs[idx], addr, len) == 0) {
      return true;
    }
  }
  return false;
}

void Scheduler::SyscallConnect(int *ret, int sockfd, void *addr, uptr addrlen, Syscallback *syscallback) {
  //Printf("Intercepting: connect %d -> %s\n", sockfd, (const char *)(addr) + 2);
  syscallback->Call();
  const char *path = (const char *)(addr) + sizeof(short);
  uptr path_len = addrlen - sizeof(short);
  while (*path == 0 && --path_len > 0) {
    ++path;
  }
  Printf("Intercepting: connect %d -> %s\n", sockfd, path);
  if (!SyscallIsInputFd(path, path_len)) {
    input_fd_[sockfd] = false;
    return;
  }
  CHECK(sockfd < kMaxFd && "Socket fd too large.");
  input_fd_[sockfd] = true;
  int real_ret = *ret;
  int replay_fd = sockfd;
  void *params[2] = {ret, &replay_fd};
  uptr param_size[2] = {sizeof(int), sizeof(int)};
  ScopedScheduler(this, cur_thread());
  DemoPlaySyscallNext("connect", 2, params, param_size);
  CHECK(real_ret == *ret);
  fd_map_[replay_fd] = sockfd;
  DemoRecordSyscallNext("connect", 2, params, param_size);
}

void Scheduler::SyscallIoctl(
    int *ret, int fd, unsigned long request, void *arg) {
  //Printf("Intercepting: ioctl %d\n", fd);
  //void *params[2] = {ret, arg};
  //uptr param_size[2] = {sizeof(int), IOC_SIZE(request)};
  //DemoPlaySyscallNext("ioctl", 2, params, param_size);
  //DemoRecordSyscallNext("ioctl", 2, params, param_size);
}

void Scheduler::SyscallPoll(int *ret, void *fds, unsigned nfds, int timeout, Syscallback *syscallback) {
  //Printf("Intercepting: poll");
  syscallback->Call();
  int errno_ = *__errno_location();
  __sanitizer_pollfd *poll_fds = (__sanitizer_pollfd *)fds;
  CHECK(nfds <= 12 && "Error: too many buffers in poll");
  // Separate input fds from non-input to be recorded.
  uptr icount = 0;
  void *params[26] = {ret};
  uptr param_size[26] = {sizeof(int)};
  for (uptr p = 0; p < nfds; ++p) {
    if (!input_fd_[poll_fds[0].fd]) {
      continue;
    }
    params[2 * icount + 1] = &poll_fds[p].events;
    param_size[2 * icount + 1] = sizeof(poll_fds[p].events);
    params[2 * icount + 2] = &poll_fds[p].revents;
    param_size[2 * icount + 2] = sizeof(poll_fds[p].revents);
    ++icount;
  }
  params[2 * icount + 1] = &errno_;
  param_size[2 * icount + 1] = sizeof(int);
  if (icount == 0) {
    *__errno_location() = errno_;
    return;
  }
  // TODO If there is a mix on input fds and non-input fds.
  // Record another var that indicated if non-input fds unblocked thread.
  CHECK(icount == nfds);
  ScopedScheduler scoped(this, cur_thread());
  DemoPlaySyscallNext("poll", 2 * nfds + 2, params, param_size);
  DemoRecordSyscallNext("poll", 2 * nfds + 2, params, param_size);
  *__errno_location() = errno_;
}

void Scheduler::SyscallRecv(
    sptr *ret, int sockfd, void *buf, uptr len, int flags, Syscallback *syscallback) {
 // Printf("Intercepting: recv\n");
  syscallback->Call();
  int errno_ = *__errno_location();
  if (!input_fd_[sockfd]) {
    return;
  }
  void *params[3] = {ret, buf, &errno_};
  uptr param_size[3] = {sizeof(sptr), len, sizeof(int)};
  ScopedScheduler(this, cur_thread());
  DemoPlaySyscallNext("recv", 3, params, param_size);
  DemoRecordSyscallNext("recv", 3, params, param_size);
  *__errno_location() = errno_;
}

void Scheduler::SyscallRecvfrom(
    sptr *ret, int sockfd, void *buf, uptr len, int flags,
    void *src_addr, int *addrlen, uptr addrlen_pre) {
  //Printf("Intercepting: recvfrom\n");
  if (!input_fd_[sockfd]) {
    return;
  }
  void *params[4] = {ret, buf, src_addr, addrlen};
  uptr param_size[4] = {sizeof(sptr), len, addrlen_pre, sizeof(int)};
  ScopedScheduler(this, cur_thread());
  DemoPlaySyscallNext("recvfrom", 2, params, param_size);
  DemoRecordSyscallNext("recvfrom", 2, params, param_size);
}

void Scheduler::SyscallRecvmsg(sptr *ret, int sockfd, void *msghdr, int flags, Syscallback *syscallback) {
  //Printf("Intercepting: recvmsg %d\n", sockfd);
  syscallback->Call();
  int errno_ = *__errno_location();
  if (!input_fd_[sockfd]) {
    return;
  }
  __sanitizer_msghdr *msg = (__sanitizer_msghdr *)msghdr;
  CHECK(msg->msg_iovlen <= 16 && "Error: too many buffers in recvmsg");
  void *params[22] = {ret};
  uptr param_size[22] = {sizeof(sptr)};
  for (uptr p = 0; p < msg->msg_iovlen; ++p) {
    params[p + 1] = msg->msg_iov[p].iov_base;
    param_size[p + 1] = msg->msg_iov[p].iov_len;
  }
  params[msg->msg_iovlen + 1] = msg->msg_name;
  param_size[msg->msg_iovlen + 1] = msg->msg_namelen;
  params[msg->msg_iovlen + 2] = &param_size[msg->msg_iovlen + 3];
  param_size[msg->msg_iovlen + 2] = sizeof(uptr);
  params[msg->msg_iovlen + 3] = msg->msg_control;
  param_size[msg->msg_iovlen + 3] = msg->msg_controllen;
  params[msg->msg_iovlen + 4] = &msg->msg_flags;
  param_size[msg->msg_iovlen + 4] = sizeof(int);
  params[msg->msg_iovlen + 5] = &errno_;
  param_size[msg->msg_iovlen + 5] = sizeof(int);
  ScopedScheduler scoped(this, cur_thread());
  DemoPlaySyscallNext("recvmsg", msg->msg_iovlen + 6, params, param_size);
  msg->msg_controllen = param_size[msg->msg_iovlen + 3];
  DemoRecordSyscallNext("recvmsg", msg->msg_iovlen + 6, params, param_size);
  *__errno_location() = errno_;
}

void Scheduler::SyscallSendmsg(sptr *ret, int sockfd, void *msghdr, int flags, Syscallback *syscallback) {
  syscallback->Call();
  int errno_ = *__errno_location();
  if (!input_fd_[sockfd]) {
    return;
  }
  void *params[2] = {ret, &errno_};
  uptr param_size[2] = {sizeof(sptr), sizeof(int)};
  ScopedScheduler scoped(this, cur_thread());
  DemoPlaySyscallNext("sendmsg", 2, params, param_size);
  DemoRecordSyscallNext("sendmsg", 2, params, param_size);
  *__errno_location() = errno_;
}

void Scheduler::SyscallSelect(
    int *ret, int nfds, void *readfds, void *writefds, void *exceptfds,
    void *timeout, void *select) {
  //Printf("Intercepting: select %d %p %p %p\n", nfds, readfds, writefds, exceptfds);
  // Check for a mix of input and non-input, which cannot be done for now.
  void *fd_sets[3] = {readfds, writefds, exceptfds};
  bool has_input = false;
  bool has_noninput = false;
  for (int set = 0; set < 3; ++set) {
    void *fd_set = fd_sets[set];
    if (fd_set == nullptr) {
      continue;
    }
    for (int fd = 0; fd < nfds; ++fd) {
      if (FD_ISSET(fd, fd_set)) {
        (input_fd_[fd] ? has_input : has_noninput) = true;
      }
    }
  }
  CHECK(!(has_input && has_noninput) && "Input and non-input in select()");
  // Actual syscall.
  typedef int (*select_t)(int, void *, void *, void *, void *);
  select_t select_ = (select_t)select;
  *ret = select_(nfds, readfds, writefds, exceptfds, timeout);
  if (!has_input) {
    return;
  }
  int errno_ = *__errno_location();
  // Set dummy fd sets to replay into.
  __sanitizer___kernel_fd_set readfds_, writefds_, exceptfds_;
  void *params[5] = {ret, &errno_, &readfds_, &writefds_, &exceptfds_};
  uptr param_size[5] =
      {sizeof(sptr), sizeof(int), kMaxFd / 8, kMaxFd / 8, kMaxFd / 8};
  // Manually set critical section and record/replay.
  {
    ScopedScheduler scoped(this, cur_thread());
    DemoPlaySyscallNext("select", 5, params, param_size);
    DemoRecordSyscallNext("select", 5, params, param_size);
  }
  // Using the fd_map, set the fds for the actual fd_sets.
  void *fd_sets_[3] = {&readfds_, &writefds_, &exceptfds_};
  for (int set = 0; set < 3; ++set) {
    void *fd_set = fd_sets[set];
    void *fd_set_ = fd_sets_[set];
    if (fd_set == nullptr) {
      continue;
    }
    FD_ZERO(fd_set);
    for (int fd = 0; fd < kMaxFd; ++fd) {
      if (FD_ISSET(fd, fd_set_)) {
        FD_SET(fd_map_[fd], fd_set);
      }
    }
  }
}

void Scheduler::FileCreate(const char *file, int *fd_replay, int *fd_record) {
  char path[256];
  internal_snprintf(path, 256, "%s", file);
  for (int idx = 0; idx < 256 && path[idx] != '\0'; ++idx) {
    if (path[idx] == '/') {
      path[idx] = '.';
    }
  }

  if (flags()->play_demo && flags()->play_demo[0]) {
    InternalScopedBuffer<char> buf(512);
    internal_snprintf(buf.data(), buf.size(), "%s/FS%d/%s%d",
        flags()->play_demo, pid_, path, tick_);
    *fd_replay = OpenFile(buf.data(), WrOnly);
  }
  if (flags()->record_demo && flags()->record_demo[0]) {
    InternalScopedBuffer<char> buf(512);
    internal_snprintf(buf.data(), buf.size(), "%s/FS%d/%s%d",
        flags()->record_demo, pid_, path, tick_);
    *fd_record = OpenFile(buf.data(), WrOnly);
  }
}


////////////////////////////////////////
// PRNG utilities.
////////////////////////////////////////

u64 Scheduler::RandomNumber() {
  // Reading from file only supports s64, not u64. So the MSB must be 0.
  return xorshift128plus() >> 1;
}

u64 Scheduler::RandomNext(ThreadState *thr, EventType event_type) {
  if (exclude_point_[thr->tid] == 1) {
    return 1;
  }
  if (DemoPlayActive() && tick_ > demo_play_.demo_tick_) {
    DemoPlayNext();
  }
  u64 return_param;
  if (DemoPlayActive() && tick_ == demo_play_.demo_tick_) {
    CHECK(event_type == demo_play_.event_type_);
    return_param = (u64)-1;
    DemoRecordNext(
        tick_, event_type, demo_play_.event_param_, demo_play_.rnd_skip_);
  } else {
    return_param = RandomNumber();
  }
  ++tick_;
  return return_param;
}


////////////////////////////////////////
// Annotations.
////////////////////////////////////////

void Scheduler::AnnotateExcludeEnter() {
  ThreadState *thr = cur_thread();
  Wait(thr);
  atomic_store(&cond_vars_[thr->tid], kActive, memory_order_relaxed);
  exclude_point_[thr->tid] = 1;
}

void Scheduler::AnnotateExcludeExit() {
  ThreadState *thr = cur_thread();
  exclude_point_[thr->tid] = 0;
  atomic_store(&cond_vars_[thr->tid], kCritical, memory_order_relaxed);
  Tick(thr);
}

void Scheduler::AEx() { ctx->scheduler.AnnotateExcludeEnter(); }
void Scheduler::ARe() { ctx->scheduler.AnnotateExcludeExit(); }


////////////////////////////////////////
// Other internal utilities.
////////////////////////////////////////

void Scheduler::Enable(int tid) {
  cond_vars_idx_[last_free_idx_] = tid;
  cond_vars_idx_inv_[tid] = last_free_idx_++;
  thread_status_[tid] = RUNNING;
  pri_[tid] = kMaxPri;
}

void Scheduler::Disable(int tid) {
  int tid_last_idx = cond_vars_idx_[--last_free_idx_];
  cond_vars_idx_[cond_vars_idx_inv_[tid]] = tid_last_idx;
  cond_vars_idx_inv_[tid_last_idx] = cond_vars_idx_inv_[tid];
  thread_status_[tid] = DISABLED;
}

void Scheduler::PrintUserSanitizerStackBoundary() {
  ThreadState *thr = cur_thread();
  if (thr->shadow_stack == 0) {
    return;
  }
  Symbolizer *symbolizer = Symbolizer::GetOrInit();
  // Get top of user stack.
  uptr addr = thr->shadow_stack_pos[-1];
  SymbolizedStack *stack = symbolizer->SymbolizePC(addr);
  Printf("%s at %s:%d",
      stack->info.function, stack->info.file, stack->info.line);
  stack->ClearAll();
  // Get bottom of sanitizer stack.
  uhwptr *bp = (uhwptr *)GET_CURRENT_FRAME();
  uhwptr pc = bp[1] + 0x40;
  //while ((uptr)pc != addr) {
  //  bp = (uhwptr *)bp[0];
  //  pc = bp[1];
  //}
  stack = symbolizer->SymbolizePC((uptr)pc);
  Printf(" -> %s", stack->info.function);
  stack->ClearAll();
}


////////////////////////////////////////
// Demo playback.
////////////////////////////////////////

void Scheduler::DemoPlayInitialise() {
  demo_play_.play_demo_ = flags()->play_demo && flags()->play_demo[0];
  demo_play_.event_type_ = END;
  if (!demo_play_.play_demo_ || !flags()->play_demo[0]) {
    return;
  }
  uptr buffer_size;
  uptr contents_size;
  char buf[128];
  internal_snprintf(buf, 128, "%s/%d", flags()->play_demo, pid_);
  CHECK(ReadFileToBuffer(
      buf, &demo_play_.demo_contents_, &buffer_size, &contents_size));
  CHECK(demo_play_.demo_contents_[0] != 0);
  s[0] = internal_simple_strtoll(
      demo_play_.demo_contents_, &demo_play_.demo_contents_, 10);
  CHECK(demo_play_.demo_contents_[0] != 0);
  s[1] = internal_simple_strtoll(
      demo_play_.demo_contents_, &demo_play_.demo_contents_, 10);
  DemoPlayNext();
  // SIGNAL setup
  internal_snprintf(buf, 128, "%s/SIGNAL", flags()->play_demo);
  CHECK(ReadFileToBuffer(
      buf, &demo_play_.signal_contents_, &buffer_size, &contents_size));
  for (int tid = 0; tid < kNumThreads; ++tid) {
    DemoPlaySignalNext(tid);
  }
  // SYSCALL setup
  internal_snprintf(buf, 128, "%s/SYSCALL", flags()->play_demo);
  CHECK(ReadFileToBuffer(
      buf, &demo_play_.syscall_contents_, &buffer_size, &contents_size));
}

void Scheduler::DemoPlayNext() {
  if (!demo_play_.play_demo_ || demo_play_.demo_contents_[0] == '\0') {
    demo_play_.event_param_ = END;
    return;
  }
  demo_play_.demo_tick_ = internal_simple_strtoll(
      demo_play_.demo_contents_, &demo_play_.demo_contents_, 10);
  demo_play_.event_type_ = (EventType)internal_simple_strtoll(
      demo_play_.demo_contents_, &demo_play_.demo_contents_, 10);
  demo_play_.event_param_ = internal_simple_strtoll(
      demo_play_.demo_contents_, &demo_play_.demo_contents_, 10);
  demo_play_.rnd_skip_ = internal_simple_strtoll(
      demo_play_.demo_contents_, &demo_play_.demo_contents_, 10);
}

bool Scheduler::DemoPlayActive() {
  return demo_play_.play_demo_ && demo_play_.event_type_ != END;
}

bool Scheduler::DemoPlayEnabled() {
  return demo_play_.play_demo_;
}

void Scheduler::DemoPlayCheck(
    u64 demo_tick, EventType event_type, u64 param1, u64 param2) {
  if (!DemoPlayActive()) {
    return;
  }
  CHECK(demo_tick == (u64)-1 || demo_tick == demo_play_.demo_tick_);
  CHECK(event_type == END || event_type == demo_play_.event_type_);
  CHECK(param1 == (u64)-1 || param1 == demo_play_.event_param_);
  CHECK(param2 == (u64)-1 || param1 == demo_play_.rnd_skip_);
}

bool Scheduler::DemoPlayExpectParam1(u64 param1) {
  return !DemoPlayActive() || param1 == demo_play_.event_param_;
}

bool Scheduler::DemoPlayExpectParam2(u64 param2) {
  return !DemoPlayActive() || param2 == demo_play_.rnd_skip_;
}

void Scheduler::DemoPlaySignalNext(int tid) {
  int signal_tid = internal_simple_strtoll(
      demo_play_.signal_contents_, &demo_play_.signal_contents_, 10);
  CHECK(signal_tid == tid && "Error: Signal file has desynchronised");
  demo_play_.signal_tick_[tid] = internal_simple_strtoll(
      demo_play_.signal_contents_, &demo_play_.signal_contents_, 10);
  demo_play_.signal_num_[tid] = internal_simple_strtoll(
      demo_play_.signal_contents_, &demo_play_.signal_contents_, 10);
}

void Scheduler::DemoPlaySyscallNext(
    const char *func, uptr param_count, void *param[], uptr param_size[]) {
  if (!/*DemoPlayActive()*/DemoPlayEnabled() || /*tsanstart == 0*/exclude_point_[cur_thread()->tid] == 1) {
    return;
  }
  uptr func_size = internal_strlen(func);
  CHECK(internal_strncmp(func, demo_play_.syscall_contents_, func_size) == 0 &&
        "Error: Syscall file has desynchronised");
  demo_play_.syscall_contents_ += func_size;
  for (uptr p = 0; p < param_count; ++p) {
    sptr count = param_size[p];
    unsigned char *data = (unsigned char *)param[p];
    while (count != 0) {
      CHECK(count > 0);
      unsigned char flag = *((unsigned char *)demo_play_.syscall_contents_);
      if (flag == (1 << 7)) {
        uptr block = 32 < count ? 32 : count;
        ++demo_play_.syscall_contents_;
        internal_memcpy(data, demo_play_.syscall_contents_, block);
        count -= block;
        demo_play_.syscall_contents_ += block;
        data += block;
        continue;
      }
      unsigned block = flag & ((1 << 6) - 1);
      if (flag & (1 << 6)) {
        unsigned char high = *++demo_play_.syscall_contents_;
        block |= ((unsigned)high << 6);
        if (block == 0) {
          block = 1 << 14;
        }
      }
      internal_memset(data, 0, block);
      count -= block;
      ++demo_play_.syscall_contents_;
      data += block;
    }
  }
}

void Scheduler::DemoPlaySyscallNextCheck() {
  if (!/*DemoPlayActive()*/DemoPlayEnabled()) {
    return;
  }
  const char * const syscalls[6] =
      {"recvmsg", "recv", "poll", "ioctl", "connect", "time"};
  const uptr syssize[6] = {7, 4, 4, 5, 7, 4};
  for (uptr sys = 0; sys < 6; ++sys) {
    if (internal_strncmp(
        syscalls[sys], demo_play_.syscall_contents_, syssize[sys]) == 0) {
      return;
    }
  }
  CHECK(false && "Error: Next syscall inconsistent");
}


////////////////////////////////////////
// Demo record.
////////////////////////////////////////

void Scheduler::DemoRecordInitialise() {
  demo_record_.record_fd_ = kInvalidFd;
  if (!flags()->record_demo || !flags()->record_demo[0]) {
    return;
  }
  char buf[128];
  internal_snprintf(buf, 128, "%s/%d", flags()->record_demo, pid_);
  demo_record_.record_fd_ = OpenFile(buf, WrOnly);
  internal_snprintf(buf, 128, "%llu %llu\n", s[0], s[1]);
  WriteToFile(demo_record_.record_fd_, buf, internal_strlen(buf));
  demo_record_.demo_tick_ = -1;
  demo_record_.event_type_ = END;
  // SIGNAL setup
  internal_snprintf(buf, 128, "%s/SIGNAL", flags()->record_demo);
  demo_record_.signal_fd_ = OpenFile(buf, WrOnly);
  for (int tid = 0; tid < kNumThreads; ++tid) {
    demo_record_.signal_file_pos_[tid] =
        internal_lseek(demo_record_.signal_fd_, 0, SEEK_CUR);
    demo_record_.signal_tick_[tid] = -1;
    demo_record_.signal_num_[tid] = 0;
    DemoRecordSignalLine(buf, tid, -1, 0);
    WriteToFile(demo_record_.signal_fd_, buf, internal_strlen(buf));
  }
  // SYSCALL setup
  internal_snprintf(buf, 128, "%s/SYSCALL", flags()->record_demo);
  demo_record_.syscall_fd_ = OpenFile(buf, WrOnly);
}

void Scheduler::DemoRecordFinalise() {
  if (!DemoRecordEnabled()) {
    return;
  }
  // First call writes the previous entry, second call wites the END entry.
  DemoRecordNext(tick_, END, 0, 0);
  DemoRecordNext(tick_, END, 0, 0);
  // Signal
  for (int tid = 0; tid < kNumThreads; ++tid) {
    if (demo_record_.signal_tick_[tid] != (u64)-1) {
      internal_lseek(demo_record_.signal_fd_,
          demo_record_.signal_file_pos_[tid], SEEK_SET);
      char line[65];
      DemoRecordSignalLine(line,
          tid, demo_record_.signal_tick_[tid], demo_record_.signal_num_[tid]);
      WriteToFile(demo_record_.signal_fd_, line, 64);
    }
  }
}

void Scheduler::DemoRecordNext(u64 tick, EventType type, u64 param, u64 rnd_skip) {
  if (!DemoRecordEnabled()) {
    return;
  }
  if (demo_record_.demo_tick_ != (u64)-1) {
    char buf[128];
    internal_snprintf(buf, 128, "%llu %llu %llu %llu\n",
        demo_record_.demo_tick_, demo_record_.event_type_,
        demo_record_.event_param_, demo_record_.rnd_skip_);
    WriteToFile(demo_record_.record_fd_, buf, internal_strlen(buf));
  }
  demo_record_.demo_tick_ = tick;
  demo_record_.event_type_ = type;
  demo_record_.event_param_ = param;
  demo_record_.rnd_skip_ = rnd_skip;
}

bool Scheduler::DemoRecordEnabled() {
  return demo_record_.record_fd_ != kInvalidFd;
}

void Scheduler::DemoRecordOverride(
    u64 tick, EventType type, u64 param, u64 rnd_skip) {
  if (!DemoRecordEnabled()) {
    return;
  }
  if (demo_record_.demo_tick_ == tick) {
    // If the current tick has demo information.
    CHECK(demo_record_.event_type_ == type);
    demo_record_.event_param_ = param;
    demo_record_.rnd_skip_ += rnd_skip;
  } else {
    // No demo information. It is the previous tick we are rescheduling.
    DemoRecordNext(tick, type, param, rnd_skip);
  }
}

void Scheduler::DemoRecordSignalNext(int tid, u64 signal_tick, int signum) {
  if (!DemoRecordEnabled()) {
    return;
  }
  // If this is a signal on a new tick, the old one must be written to its
  // position in file and a new part of the file must be allocated.
  if (demo_record_.signal_tick_[tid] == (u64)-1) {
    demo_record_.signal_tick_[tid] = signal_tick;
    demo_record_.signal_num_[tid] = (1 << (signum - 1));
    return;
  }
  if (signal_tick != demo_record_.signal_tick_[tid]) {
    uptr restore = internal_lseek(demo_record_.signal_fd_, 0, SEEK_CUR);
    internal_lseek(demo_record_.signal_fd_,
        demo_record_.signal_file_pos_[tid], SEEK_SET);
    char line[65];
    DemoRecordSignalLine(line,
        tid, demo_record_.signal_tick_[tid], demo_record_.signal_num_[tid]);
    WriteToFile(demo_record_.signal_fd_, line, 64);
    internal_lseek(demo_record_.signal_fd_, restore, SEEK_SET);
    demo_record_.signal_file_pos_[tid] = restore;
    DemoRecordSignalLine(line, tid, -1, 0);
    WriteToFile(demo_record_.signal_fd_, line, 64);
    // Refresh this thread's signal info.
    demo_record_.signal_tick_[tid] = signal_tick;
    demo_record_.signal_num_[tid] = 0;
  }
  demo_record_.signal_num_[tid] |= (1 << (signum - 1));
}

void Scheduler::DemoRecordSignalLine(
    char *buf, int tid, u64 signal_tick, int signum) {
  static const int kLineLength = 64;
  int written = internal_snprintf(buf, kLineLength + 1, "%llu %llu %llu",
      tid, signal_tick, signum);
  CHECK(written <= kLineLength);
  internal_memset(&buf[written], ' ', kLineLength - written - 1);
  buf[kLineLength - 1] = '\n';
  buf[kLineLength] = '\0';
}

void Scheduler::DemoRecordSyscallNext(
    const char *func, uptr param_count, void *param[], uptr param_size[]) {
  if (!DemoRecordEnabled() || /*tsanstart == 0*/exclude_point_[cur_thread()->tid] == 1) {
    return;
  }
  WriteToFile(demo_record_.syscall_fd_, func, internal_strlen(func));
  //for (uptr p = 0; p < param_count; ++p) {
  //  WriteToFile(demo_record_.syscall_fd_, param[p], param_size[p]);
  //}
  for (uptr p = 0; p < param_count; ++p) {
    uptr count = param_size[p];
    unsigned char *data = (unsigned char *)param[p];
    while (count != 0) {
      CHECK(count > 0);
      if (*data != 0) {
        // Set flag bit to 1 and encode next 32 bytes as is.
        uptr block = 32 < count ? 32 : count;
        unsigned char type = 1 << 7;
        WriteToFile(demo_record_.syscall_fd_, &type, 1);
        WriteToFile(demo_record_.syscall_fd_, data, block);
        count -= block;
        data += block;
        continue;
      }
      unsigned block = 1;
      ++data;
      while (block < (1 << 14) && block < count && *data == 0) {
        ++block;
        ++data;
      }
      // Set flag bit to 0 and collapse up to 16383 0s.
      unsigned char type = 0;
      type |= (block >= 64 ? (1 << 6) : 0);
      type |= (block & ((1 << 6) - 1));
      WriteToFile(demo_record_.syscall_fd_, &type, 1);
      if (block >= 64) {
        unsigned char high = block >> 6;
        WriteToFile(demo_record_.syscall_fd_, &high, 1);
      }
      count -= block;
    }
  }
  DemoPlaySyscallNextCheck();
}

}  // namespace __tsan
