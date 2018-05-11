// First come first serve shceduler stuff.

#include "tsan_schedule.h"

#include "interception/interception.h"
#include "tsan_rtl.h"

DECLARE_REAL(SSIZE_T, pwrite, int fd, void *ptr, SIZE_T count, OFF_T offset)

namespace __tsan {
namespace {

// First come first serve queue.
// Grab queue_head and wait until queue_tail catches up.
atomic_uint64_t queue_head;
atomic_uint64_t queue_tail;

// For disable/enable. Prevents a thread from queueing up if it is blocked.
const int kEnabled = 0;
const int kDisabled = 1;
atomic_uintptr_t enabled[Scheduler::kNumThreads];

// Time slicing is racy with respect to Reschedule(), so they must both close
// and open the gate before they can proceed.
const int kOpen = 1;
const int kClosed = 0;
//atomic_uintptr_t slice_gate_[Scheduler::kNumThreads];

// For demo play. This strategy has an extra 'QUEUE' file that threads will read
// from, instead of taking queue_head.
char *demo_contents_;
u64 demo_play_queue_pos_[Scheduler::kNumThreads];

// For demo record. Write queue_head for each tick to 'QUEUE'.
// The 'QUEUE' file will been written to in such a way that the order matches
// the order in which threads will access it upon playback.
// If a thread is run for multiple consecutive queue positions, these are
// compacted as 'history'.
fd_t record_fd_;
u64 demo_record_file_pos_[Scheduler::kNumThreads];

// Compactor mechanism for demo recording. Takes the recent history and tries to
// compact it into fewer lines in 'QUEUE'.
int demo_record_last_tid_;
u64 demo_record_last_pos_;
int demo_play_last_tid_;
u64 demo_play_queue_end_;

// Data used to pull file operations out of the critical section.
// Put relevant info in thr->tid index and use it at the end of Tick().
// The 'pwrite' system call allows for parallel write.
u64 demo_record_queue_[Scheduler::kNumThreads];
int demo_record_re_tid_[Scheduler::kNumThreads];
u64 demo_record_re_pos_[Scheduler::kNumThreads];
u64 demo_record_pos_[Scheduler::kNumThreads];
u64 foff;
const int kLineLength = 12;

void QueueDemoPlayNext(int tid);
void QueueDemoRecordLine(char *buf, int tid, u64 pos);
void QueueDemoRecordRepeat(char *buf, int tid, u64 count);

// Initialise the demo play system specific to the queue strategy.
void QueueDemoPlayInitialise() {
  // Open demo play file.
  if (flags()->play_demo && flags()->play_demo[0]) {
    uptr buffer_size;
    uptr contents_size;
    char buf[128];
    internal_snprintf(buf, 128, "%s/%d-queue", flags()->play_demo, 0);
    CHECK(ReadFileToBuffer(buf, &demo_contents_, &buffer_size, &contents_size));
    for (int idx = 0; idx < 80; ++idx) {
      QueueDemoPlayNext(idx);
    }
  } else {
    demo_contents_ = nullptr;
    for (int idx = 0; idx < 80; ++idx) {
      demo_play_queue_pos_[idx] = 0;
    }
  }
  demo_play_last_tid_ = -1;
  demo_play_queue_end_ = 0;
}

// Read the next queue position for the current thread from 'QUEUE'.
// The current file position will be right for this thread.
void QueueDemoPlayNext(int tid) {
  if (demo_contents_ == nullptr/* || demo_contents_[0] == '\0'*/) {
    return;
  }

  // First check if history is still valid.
  u64 queue_head_= atomic_load(&queue_head, memory_order_relaxed);
  if (queue_head_ < demo_play_queue_end_) {
    CHECK(demo_play_last_tid_ == tid && "demo play error");
    demo_play_queue_pos_[tid] = queue_head_;
    return;
  }
  // If not then check if there will be.
  if (demo_contents_[0] == 'r' && demo_contents_[1] == 'e') {
    demo_play_last_tid_ = tid;
    demo_contents_ += 4;
    u32 pos;
    internal_memcpy(&pos, demo_contents_, sizeof(u32));
    demo_contents_ += sizeof(u32);
    demo_play_queue_end_ = pos;
    demo_contents_ += (kLineLength - sizeof(int) - sizeof(u32));
    demo_play_queue_pos_[tid] = queue_head_;
    // Silly, If the repeat length is 0.
    if (queue_head_ < demo_play_queue_end_) {
      return;
    }
  }

  int tid_;
  internal_memcpy(&tid_, demo_contents_, sizeof(int));
  demo_contents_ += sizeof(int);
  CHECK(tid_ == tid && "Demo play file has desynchronised.");
  u32 pos_;
  internal_memcpy(&pos_, demo_contents_, sizeof(u32));
  demo_contents_ += sizeof(u32);
  demo_play_queue_pos_[tid] = pos_;
  demo_contents_ += (kLineLength - sizeof(int) - sizeof(u32));
}

// Initialise the demo record system specific to the queue strategy.
void QueueDemoRecordInitialise() {
  // Open demo record file.
  foff = 0;
  if (flags()->record_demo && flags()->record_demo[0]) {
    char buf[128];
    internal_snprintf(buf, 128, "%s/%d-queue", flags()->record_demo, 0);
    record_fd_ = OpenFile(buf, WrOnly);
    for (int idx = 0; idx < 80; ++idx) {
      demo_record_file_pos_[idx] = foff;
      char line[65];
      QueueDemoRecordLine(line, idx, -1);
      WriteToFile(record_fd_, line, kLineLength);  // TODO remove?
      foff += kLineLength;
      demo_record_re_tid_[idx] = -1;  // demo record crit save
      demo_record_pos_[idx] = (u64)-1;  // demo record crit save
    }
  } else {
    record_fd_ = kInvalidFd;
  }
  demo_record_last_tid_ = -1;
  demo_record_last_pos_ = (u64)-1;
}

// Record the queue position for this thread in 'QUEUE', but place it in the
// position that was saved the last time this thread called this function.
// If this thread has called this multiple times in a row, then from the scond
// call, start 'history', when another thread then calls this, it will write the
// history on behalf of this thread.
// All of the writes have been moved out of here and placed at the end of
// Tick(), after the critical section, using pwrite.
void QueueDemoRecordNext(ThreadState *thr, u64 tick, u64 pos) {
  if (record_fd_ == kInvalidFd) {
    return;
  }

  // History compacting for repeating threads.
  // First see if a previous repeat needs to be stored.
  if (demo_record_last_tid_ != thr->tid && demo_record_last_pos_ != (u64)-1) {
    demo_record_re_tid_[thr->tid] = demo_record_last_tid_;
    demo_record_re_pos_[thr->tid] = demo_record_last_pos_;
    demo_record_queue_[thr->tid] = pos;
    demo_record_last_pos_ = (u64)-1;
  }
  // Now see if we are repeating.
  if (demo_record_last_tid_ == thr->tid) {
    // Are there already repeat line reserved in the demo file?
    if (demo_record_last_pos_ != (u64)-1) {
      return;
    }
    // No? Write "re -1", marking the position for another thread to overwrite.
    demo_record_last_pos_ = foff;
    foff += kLineLength;
  } else {
    // First consecutive write. Fall through and do the usual.
    demo_record_last_tid_ = thr->tid;
  }

  // Save current file pos.
  uptr restore = foff;
  foff += kLineLength;
  // Write the previous entry.
  demo_record_queue_[thr->tid] = pos;
  demo_record_pos_[thr->tid] = demo_record_file_pos_[thr->tid];
  demo_record_file_pos_[thr->tid] = restore;
}

// Utility to declutter record methods.
// Writes the tid and queue position to a 12 byte buffer.
void QueueDemoRecordLine(char *buf, int tid, u64 pos) {
  static const uptr kPadLength = kLineLength - sizeof(int) - sizeof(u32) - 1;
  u32 pos_ = pos;
  internal_memcpy(buf, &tid, sizeof(int));
  buf += sizeof(int);
  internal_memcpy(buf, &pos_, sizeof(u32));
  buf += sizeof(u32);
  internal_memset(buf, ' ', kPadLength);
  buf[kPadLength] = '\n';
  buf[kPadLength + 1] = '\0';
}

// Utility to declutter record methods.
// Writes "re" and history length to a 12 byte buffer.
void QueueDemoRecordRepeat(char *buf, int tid, u64 count) {
  static const uptr kPadLength = kLineLength - 4 - sizeof(u32) - 1;
  u32 pos_ = count;
  buf[0] = 'r';
  buf[1] = 'e';
  buf[2] = 0;
  buf[3] = 0;
  buf += 4;
  internal_memcpy(buf, &pos_, sizeof(u32));
  buf += sizeof(u32);
  internal_memset(buf, ' ', kPadLength);
  buf[kPadLength] = '\n';
  buf[kPadLength + 1] = '\0';
}

}  // namespace


// The functions below are still a part of the main scheduler.

void Scheduler::StrategyQueueInitialise() {
  WaitFunc       = &Scheduler::StrategyQueueWait;
  TickFunc       = &Scheduler::StrategyQueueTick;
  EnableFunc     = &Scheduler::StrategyQueueEnable;
  DisableFunc    = &Scheduler::StrategyQueueDisable;
  RescheduleFunc = &Scheduler::StrategyQueueReschedule;
  atomic_store(&queue_head, 0, memory_order_relaxed);
  atomic_store(&queue_tail, 0, memory_order_relaxed);
  atomic_store(&enabled[0], kEnabled, memory_order_relaxed);
  QueueDemoPlayInitialise();
  QueueDemoRecordInitialise();
}

void Scheduler::StrategyQueueWait(ThreadState *thr) {
  if (exclude_point_[thr->tid] == 1) {
    // TODO reschedule?
    return;
  }
  // Is thread blocked (e.g. mutex lock fail).
  uptr stat = kEnabled;
  while (!atomic_compare_exchange_strong(
      &enabled[thr->tid], &stat, kEnabled, memory_order_relaxed)) {
    // TODO dynamic wait method.
    stat = kEnabled;
    proc_yield(20);
  }
  u64 pos = atomic_fetch_add(&queue_tail, 1, memory_order_relaxed);
  pos = demo_play_queue_pos_[thr->tid] != 0 ?
      demo_play_queue_pos_[thr->tid] : pos;
  // Has queue caught up yet.
  u64 cmp = pos;
  while (!atomic_compare_exchange_strong(
      &queue_head, &cmp, pos, memory_order_relaxed)) {
    CHECK(cmp <= pos && "Uh oh!");  // Only for reschedule
    cmp = pos;
    proc_yield(20);
  }
}

void Scheduler::StrategyQueueTick(ThreadState *thr) {
  mtx.Lock();
  // DEBUG
  //Printf("%d - %d - ", thr->tid, tick_);
  //PrintUserSanitizerStackBoundary();
  //Printf("\n");
  if (exclude_point_[thr->tid] == 1 && thread_status_[thr->tid] != DISABLED) {
    mtx.Unlock();
    return;
  }
  SignalPending(thr);
  u64 pos = atomic_fetch_add(&queue_head, 1, memory_order_relaxed);
  QueueDemoPlayNext(thr->tid);
  QueueDemoRecordNext(thr, tick_, pos);
  ++tick_;
  mtx.Unlock();
  // This is part of record, which has been pulled out to free the lock.
  char line[33];
  if (demo_record_re_tid_[thr->tid] != -1) {
    QueueDemoRecordRepeat(line, demo_record_re_tid_[thr->tid], demo_record_queue_[thr->tid]);
    REAL(pwrite)(record_fd_, line, 12, demo_record_re_pos_[thr->tid]);
    demo_record_re_tid_[thr->tid] = -1;
  }
  if (demo_record_pos_[thr->tid] != (u64)-1) {
    QueueDemoRecordLine(line, thr->tid, demo_record_queue_[thr->tid]);
    REAL(pwrite)(record_fd_, line, 12, demo_record_pos_[thr->tid]);
    demo_record_pos_[thr->tid] = (u64)-1;
  }
  // End of record
  ProcessPendingSignals(thr);
  // TODO exclude reenter
}

void Scheduler::StrategyQueueEnable(int tid) {
  thread_status_[tid] = RUNNING;
  atomic_store(&enabled[tid], kEnabled, memory_order_relaxed);
}

void Scheduler::StrategyQueueDisable(int tid) {
  thread_status_[tid] = DISABLED;
  atomic_store(&enabled[tid], kDisabled, memory_order_relaxed);
}

void Scheduler::StrategyQueueReschedule() {

}

}  // namespace __tsan
