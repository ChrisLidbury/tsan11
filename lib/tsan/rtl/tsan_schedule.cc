#include "tsan_schedule.h"

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"
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

Scheduler::Scheduler()
    : tick_(0), mtx(MutexTypeSchedule, StatMtxTotal), last_free_idx_(0) {
  internal_memset(cond_vars_, kInactive, sizeof(cond_vars_));
  internal_memset(thread_status_, FINISHED, sizeof(thread_status_));
}

Scheduler::~Scheduler() {
  if (record_fd_ != kInvalidFd)
    WriteToFile(record_fd_, "0 0 0", internal_strlen("0 0 0"));
}

// Assume this is the only scheduler.
void Scheduler::Initialise() {
  // Setup start thread.
  // This thread will still call NewThread, so do not adjust last_free_idx_.
  atomic_store(&cond_vars_[0], kActive, memory_order_relaxed);
  // Assumes ownership of PRNG buffer. Can make a member if multiple schedulers.
  s[0] = rdtsc();
  s[1] = rdtsc();

  // Set up demo playback.
  event_type_ = END;
  if (flags()->play_demo && flags()->play_demo[0]) {
    uptr buffer_size;
    uptr contents_size;
    CHECK(ReadFileToBuffer(flags()->play_demo, &demo_contents_, &buffer_size, &contents_size));
    CHECK(demo_contents_[0] != 0);
    s[0] = internal_simple_strtoll(demo_contents_, &demo_contents_, 10);
    CHECK(demo_contents_[0] != 0);
    s[1] = internal_simple_strtoll(demo_contents_, &demo_contents_, 10);
    DemoNext();
  }
  record_fd_ = kInvalidFd;
  if (flags()->record_demo && flags()->record_demo[0]) {
    record_fd_ = OpenFile(flags()->record_demo, WrOnly);
    InternalScopedBuffer<char> buf(128);
    internal_snprintf(buf.data(), buf.size(), "%llu %llu\n", s[0], s[1]);
    WriteToFile(record_fd_, buf.data(), internal_strlen(buf.data()));
  }
}

u64 Scheduler::RandomNumber() {
  // Reading from file only supports s64, not u64. So the MSB must be 0.
  return xorshift128plus() >> 1;
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
  int next_tid = RandomNext(thr, SCHEDULE);
  next_tid = last_free_idx_ == 0 ? 0 :
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
  while (atomic_load(&cond_vars_[thr->tid], memory_order_relaxed) != kActive)
    proc_yield(20);
}

// Wait and Tick are called here, unlike with atomics.
// The initial thread will call NewThread on itself, so should not be disabled.
void Scheduler::NewThread(ThreadState *thr, int tid) {
  Wait(thr);
  mtx.Lock();
  Enable(tid);
  if (thr->tid != tid)
    atomic_store(&cond_vars_[tid], kInactive, memory_order_relaxed);
  mtx.Unlock();
  Tick(thr);
}

// Replace this threads position in the last with the last.
// Mark the one past the end as active so this thread can tick.
// Wakes up parent thread if it is waiting for this thread to finish.
void Scheduler::DeleteThread(ThreadState *thr) {
  Wait(thr);
  mtx.Lock();
  Disable(thr->tid);
  thread_status_[thr->tid] = FINISHED;
  int ptid = thr->tctx->parent_tid;
  if (thread_status_[ptid] != RUNNING && wait_tid_[ptid] == thr->tid) {
    CHECK(thread_status_[ptid] != FINISHED);
    Enable(ptid);
  }
  mtx.Unlock();
  Tick(thr);
}

// Disables itself if the joining thread is not finished.
void Scheduler::JoinThread(ThreadState *thr, int join_tid) {
  Wait(thr);
  mtx.Lock();
  if (thread_status_[join_tid] != FINISHED) {
    Disable(thr->tid);
    wait_tid_[thr->tid] = join_tid;
  }
  mtx.Unlock();
  Tick(thr);
}

// random -> play_demo -> record_demo
u64 Scheduler::RandomNext(ThreadState *thr, EventType event_type) {
  u64 return_param = RandomNumber();  // Optional.
  // Read from demo file.
  if (event_type_ != END && demo_tick_ == tick_) {
    CHECK(event_type == event_type_);
    return_param = event_param_;
    // Just for the thread scheduler, lets us analyse the demo file.
    if (event_type == SCHEDULE) {
      return_param = cond_vars_idx_inv_[event_param_];
    }
    DemoNext();
  }
  // Write to demo file.
  if (record_fd_ != kInvalidFd) {
    u64 record_param = return_param;
    if (event_type == SCHEDULE) {
      record_param = cond_vars_idx_[record_param % last_free_idx_];
    }
    InternalScopedBuffer<char> buf(128);
    internal_snprintf(buf.data(), buf.size(),
        "%llu %llu %llu\n", tick_, event_type, /*return_param*/ record_param);
    WriteToFile(record_fd_, buf.data(), internal_strlen(buf.data()));
  }
  ++tick_;
  return return_param;
}

// Called by DeleteThread to enable the parent thread if necessary.
// Parent thread will automatically wake up when the child finishes.
void Scheduler::Enable(int tid) {
  cond_vars_idx_[last_free_idx_] = tid;
  cond_vars_idx_inv_[tid] = last_free_idx_++;
  thread_status_[tid] = RUNNING;
}

// Called by JoinThread to disable if child has not yet finished.
void Scheduler::Disable(int tid) {
  int tid_last_idx = cond_vars_idx_[--last_free_idx_];
  cond_vars_idx_[cond_vars_idx_inv_[tid]] = tid_last_idx;
  cond_vars_idx_inv_[tid_last_idx] = cond_vars_idx_inv_[tid];
  thread_status_[tid] = DISABLED;
}

void Scheduler::DemoNext() {
  demo_tick_ = internal_simple_strtoll(demo_contents_, &demo_contents_, 10);
  event_type_ =
      (EventType)internal_simple_strtoll(demo_contents_, &demo_contents_, 10);
  if (event_type_ != END)
    event_param_ = internal_simple_strtoll(demo_contents_, &demo_contents_, 10);
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
