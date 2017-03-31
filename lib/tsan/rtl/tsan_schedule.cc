#include "tsan_schedule.h"

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "tsan_mutex.h"
#include "tsan_rtl.h"

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
}

Scheduler::~Scheduler() {
  if (demo_record_.record_fd_ != kInvalidFd) {
    // First call writes the previous entry, second call wites the END entry.
    DemoRecordNext(tick_, END, 0, 0);
    DemoRecordNext(tick_, END, 0, 0);
  }
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

u64 Scheduler::RandomNumber() {
  // Reading from file only supports s64, not u64. So the MSB must be 0.
  return xorshift128plus() >> 1;
}

// Current thr must be active.
// Any available thread must become active.
// Locked due to ThreadDelete and for synchronisation.
void Scheduler::Tick(ThreadState *thr) {
  mtx.Lock();
  uptr cmp = kActive;
  bool is_active =
      atomic_compare_exchange_strong(&cond_vars_[thr->tid],
                                     &cmp, kInactive, memory_order_relaxed);
  CHECK(is_active);
  //int next_tid = RandomNext(thr, SCHEDULE);
  int next_tid = last_free_idx_ == 0 ? 0 :
      cond_vars_idx_[RandomNext(thr, SCHEDULE) % last_free_idx_];
  CHECK(thread_status_[next_tid] == RUNNING ||
      (next_tid == 0 && last_free_idx_ == 0));
  atomic_store(&cond_vars_[next_tid], kActive, memory_order_relaxed);
  mtx.Unlock();
}

// Must only check if it is active, not change it.
void Scheduler::Wait(ThreadState *thr) {
  //  uptr cmp = kActive;
  //  while (!atomic_compare_exchange_strong(&cond_vars_[thr->tid],
  //                                         &cmp, kActive, memory_order_relaxed))
  while (atomic_load(&cond_vars_[thr->tid], memory_order_relaxed) != kActive) {
    proc_yield(20);
  }
}

// Wait and Tick are called here, unlike with atomics.
// The initial thread will call ThreadNew on itself, so should not be disabled.
void Scheduler::ThreadNew(ThreadState *thr, int tid) {
  ScopedScheduler scoped(this, thr);
  Enable(tid);
  if (thr->tid != tid) {
    atomic_store(&cond_vars_[tid], kInactive, memory_order_relaxed);
  }
}

// Replace this threads position in the last with the last.
// Mark the one past the end as active so this thread can tick.
// Wakes up parent thread if it is waiting for this thread to finish.
void Scheduler::ThreadDelete(ThreadState *thr) {
  ScopedScheduler scoped(this, thr);
  Disable(thr->tid);
  thread_status_[thr->tid] = FINISHED;
  int ptid = thr->tctx->parent_tid;
  if (thread_status_[ptid] != RUNNING && wait_tid_[ptid] == thr->tid) {
    CHECK(thread_status_[ptid] != FINISHED);
    Enable(ptid);
    wait_tid_[ptid] = -1;
  }
}

// Disables itself if the joining thread is not finished.
void Scheduler::ThreadJoin(ThreadState *thr, int join_tid) {
  ScopedScheduler scoped(this, thr);
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

void Scheduler::FileCreate(const char *file, int *fd_replay, int *fd_record) {
  // The file within the custom FS has dir separators replaced with dots.
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

void Scheduler::Reschedule() {
  mtx.Lock();
  if (DemoPlayActive() || last_free_idx_ <= 1 || tick_ != reschedule_tick_) {
    reschedule_tick_ = tick_;
    mtx.Unlock();
    return;
  }
  // Linear search, which is OK as we only do it every 100ms.
  for (int idx = 0; idx < last_free_idx_; ++idx) {
    uptr cmp = kActive;
    bool is_active =
        atomic_compare_exchange_strong(&cond_vars_[cond_vars_idx_[idx]],
                                       &cmp, kInactive, memory_order_relaxed);
    if (!is_active) continue;
    int next_tid = cond_vars_idx_[RandomNumber() % last_free_idx_];
    CHECK(thread_status_[next_tid] == RUNNING);
    atomic_store(&cond_vars_[next_tid], kActive, memory_order_relaxed);
    DemoRecordOverride(tick_ - 1, SCHEDULE, next_tid, 1);
    break;
  }
  mtx.Unlock();
}

// random -> play_demo -> record_demo
u64 Scheduler::RandomNext(ThreadState *thr, EventType event_type) {
  u64 return_param = RandomNumber();
  if (DemoPlayActive() && tick_ == demo_play_.demo_tick_) {
    CHECK(event_type == demo_play_.event_type_);
    return_param = demo_play_.event_param_;
    u64 rnd_skip = demo_play_.rnd_skip_;
    if (event_type == SCHEDULE) {
      return_param = cond_vars_idx_inv_[demo_play_.event_param_];
    }
    while (demo_play_.rnd_skip_-- > 0) {
      RandomNumber();
    }
    DemoPlayNext();
    DemoRecordNext(tick_, event_type, cond_vars_idx_[return_param], rnd_skip);
  }
  ++tick_;
  return return_param;
}

// Called by ThreadDelete to enable the parent thread if necessary.
// Parent thread will automatically wake up when the child finishes.
void Scheduler::Enable(int tid) {
  cond_vars_idx_[last_free_idx_] = tid;
  cond_vars_idx_inv_[tid] = last_free_idx_++;
  thread_status_[tid] = RUNNING;
}

// Called by ThreadJoin to disable if child has not yet finished.
void Scheduler::Disable(int tid) {
  int tid_last_idx = cond_vars_idx_[--last_free_idx_];
  cond_vars_idx_[cond_vars_idx_inv_[tid]] = tid_last_idx;
  cond_vars_idx_inv_[tid_last_idx] = cond_vars_idx_inv_[tid];
  thread_status_[tid] = DISABLED;
}

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

}  // namespace __tsan
