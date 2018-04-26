// For queue scheduling.
// Include in the scheduler and comment out other functions with same name lol.

}
#include "interception/interception.h"
DECLARE_REAL(SSIZE_T, pwrite, int fd, void *ptr, SIZE_T count, OFF_T offset)
namespace __tsan {

namespace {
namespace WaitQueue {

// First come first serve queue
atomic_uint64_t queue_head;
atomic_uint64_t queue_tail;
// For disable/enable
static const int kEnabled = 0;
static const int kDisabled = 1;
atomic_uintptr_t enabled[80];
// For replay
u64 demo_play_queue_pos_[80];
char *demo_contents_;
// For record
u64 demo_record_queue_pos_[80];
u64 demo_record_file_pos_[80];
fd_t record_fd_;
// For history, allows compacting
int demo_record_last_tid_;  // Last tid entered
u64 demo_record_last_pos_;   // Repeat last tid until this pos.
int demo_play_last_tid_;
u64 demo_play_queue_end_;
// Extracted from record to reduce critical section, ignore.
u64 demo_record_queue_[80];
int demo_record_re_tid_[80];
u64 demo_record_re_pos_[80];
u64 demo_record_pos_[80];
u64 foff;
static const int kLineLength = 12;
// timeslice test.
u64 slice;
static const u64 slice_length_ = 100;
atomic_uintptr_t slice_gate_[80];
static const int kOpen = 1;
static const int kClosed = 0;


// Custom non-override variants of demo stuff.
void DemoPlayNext(int tid);
void DemoRecordNext(ThreadState *thr, u64 tick, u64 pos);
void DemoRecordLine(char *buf, int tid, u64 pos);
void DemoRecordRepeat(char *buf, int tid, u64 count);

// For static init of the above.
void WaitQueueInit() {
  atomic_store(&queue_head, 0, memory_order_relaxed);
  atomic_store(&queue_tail, 0, memory_order_relaxed);
  atomic_store(&enabled[0], kEnabled, memory_order_relaxed);
  for (int idx = 1; idx < 80; ++idx) {
    atomic_store(&enabled[idx], kDisabled, memory_order_relaxed);
    atomic_store(&slice_gate_[idx], kOpen, memory_order_relaxed);  // Reschedule
  }
  slice = 1;
  // Open demo play file.
  if (flags()->play_demo && flags()->play_demo[0]) {
    uptr buffer_size;
    uptr contents_size;
    char buf[128];
    internal_snprintf(buf, 128, "%s/%d-queue", flags()->play_demo, 0);
    CHECK(ReadFileToBuffer(buf, &demo_contents_, &buffer_size, &contents_size));
    for (int idx = 0; idx < 80; ++idx) {
      DemoPlayNext(idx);
    }
  } else {
    demo_contents_ = nullptr;
    for (int idx = 0; idx < 80; ++idx) {
      demo_play_queue_pos_[idx] = 0;
    }
  }
  demo_play_last_tid_ = -1;
  demo_play_queue_end_ = 0;
  // Open demo record file.
  foff = 0;  // temp
  if (flags()->record_demo && flags()->record_demo[0]) {
    char buf[128];
    internal_snprintf(buf, 128, "%s/%d-queue", flags()->record_demo, 0);
    record_fd_ = OpenFile(buf, WrOnly);
    for (int idx = 0; idx < 80; ++idx) {
      demo_record_file_pos_[idx] = foff;
      char line[65];
      DemoRecordLine(line, idx, -1);
      WriteToFile(record_fd_, line, kLineLength); // This shouls prob be removec, leave line empty.
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

}  // namespace Waiter
}  // namespace

void Scheduler::Wait(ThreadState *thr) {
  if (exclude_point_[thr->tid] == 1) {
    atomic_store(&cond_vars_[thr->tid], kCritical, memory_order_relaxed);
    return;
  }
  uptr stat = WaitQueue::kEnabled;
  while (!atomic_compare_exchange_strong(
      &WaitQueue::enabled[thr->tid], &stat, WaitQueue::kEnabled, memory_order_relaxed)) {
    stat = WaitQueue::kEnabled;
    proc_yield(20);
  }
  // Reschedule chunk
  uptr cmp_ = WaitQueue::kOpen;
  if (WaitQueue::demo_play_queue_pos_[thr->tid] != 0 &&
      !atomic_compare_exchange_strong(
          &WaitQueue::slice_gate_[thr->tid], &cmp_, WaitQueue::kClosed, memory_order_relaxed)) {
    WaitQueue::demo_play_queue_pos_[thr->tid] = 0;
    atomic_store(&WaitQueue::slice_gate_[thr->tid], WaitQueue::kOpen, memory_order_relaxed);
  }
  // End of reschedule
  u64 pos = WaitQueue::demo_play_queue_pos_[thr->tid] == 0 ?
      atomic_fetch_add(&WaitQueue::queue_tail, 1, memory_order_relaxed) :
      WaitQueue::demo_play_queue_pos_[thr->tid];
  u64 cmp = pos;
  while (!atomic_compare_exchange_strong(
      &WaitQueue::queue_head, &cmp, pos, memory_order_relaxed)) {
    CHECK(cmp <= pos && "Uh oh!");  // Only for reschedule
    cmp = pos;
    proc_yield(20);
  }
  atomic_store(&cond_vars_[thr->tid], kCritical, memory_order_relaxed);
  active_tid_ = thr->tid;  // racy
}

void Scheduler::Tick(ThreadState *thr) {
  mtx.Lock();
  uptr cmp = kCritical;
  bool is_critical = atomic_compare_exchange_strong(
      &cond_vars_[thr->tid], &cmp, kInactive, memory_order_relaxed);
  CHECK(is_critical);
  //{  // DEBUG
  //  Printf("%d - %d - ", thr->tid, tick_);
  //  PrintUserSanitizerStackBoundary();
  //  Printf("\n");
  //}
  if (exclude_point_[thr->tid] == 1 && thread_status_[thr->tid] != DISABLED) {
    mtx.Unlock();
    return;
  }
  if (WaitQueue::slice > 1 && thread_status_[thr->tid] == RUNNING) {
    --WaitQueue::slice;
    // Gross hack.
    // This entire file is actually a gross hack but this line in particular.
    WaitQueue::demo_play_queue_pos_[thr->tid] =
        atomic_load(&WaitQueue::queue_head, memory_order_relaxed);
    atomic_store(&WaitQueue::slice_gate_[thr->tid], WaitQueue::kOpen, memory_order_relaxed);  // Reschedule
    mtx.Unlock();
    return;
  }
  WaitQueue::slice = WaitQueue::slice_length_;
  WaitQueue::demo_play_queue_pos_[thr->tid] = 0; // Also gross
  active_tid_ = -1;
  atomic_store(&WaitQueue::slice_gate_[thr->tid], WaitQueue::kOpen, memory_order_relaxed);  // Reschedule
  SignalPending(thr);
  u64 pos = atomic_fetch_add(&WaitQueue::queue_head, 1, memory_order_relaxed);
  WaitQueue::DemoPlayNext(thr->tid);
  WaitQueue::DemoRecordNext(thr, tick_, pos);
  ++tick_;
  //{  // DEBUG
  //  Printf("%d - %d - ", thr->tid, pos);
  //  PrintUserSanitizerStackBoundary();
  //  Printf("\n");
  //}
  mtx.Unlock();
  // This is part of record, which has been pulled out to free the lock.
  char line[33];
  if (WaitQueue::demo_record_re_tid_[thr->tid] != -1) {
    WaitQueue::DemoRecordRepeat(line, WaitQueue::demo_record_re_tid_[thr->tid], WaitQueue::demo_record_queue_[thr->tid]);
    REAL(pwrite)(WaitQueue::record_fd_, line, 12, WaitQueue::demo_record_re_pos_[thr->tid]);
    WaitQueue::demo_record_re_tid_[thr->tid] = -1;
  }
  if (WaitQueue::demo_record_pos_[thr->tid] != (u64)-1) {
    WaitQueue::DemoRecordLine(line, thr->tid, WaitQueue::demo_record_queue_[thr->tid]);
    REAL(pwrite)(WaitQueue::record_fd_, line, 12, WaitQueue::demo_record_pos_[thr->tid]);
    WaitQueue::demo_record_pos_[thr->tid] = (u64)-1;
  }
  // End of record
  ProcessPendingSignals(thr);
  // If this was excluded, it must exit and reenter.
  if (exclude_point_[thr->tid] == 1) {
    exclude_point_[thr->tid] = 0;
    Wait(thr);
    exclude_point_[thr->tid] = 1;
  }
}

void Scheduler::Reschedule() {  // DOES NOT WORK WITH REC/REP.
  if (WaitQueue::slice_length_ < 2) {
    return;
  }
  static u64 slice = 0;
  static u64 head = 0;
  mtx.Lock();
  u64 slice_ = WaitQueue::slice;
  u64 head_ = atomic_load(&WaitQueue::queue_head, memory_order_relaxed);
  // Not in the middle of a slice.
  if (slice_ == WaitQueue::slice_length_) {
    mtx.Unlock();
    return;
  }
  // Have advanced since last Reschedule().
  if (!(slice_ == slice && head_ == head)) {
    slice = slice_;
    head = head_;
    mtx.Unlock();
    return;
  }
  // This is still racy if the active tid has passed the queue check but not set
  // the active_tid.
  int tid = active_tid_;
  if (exclude_point_[tid] == 1) {
    mtx.Unlock();
    return;
  }
  CHECK(tid != -1 && "Oops!");
  // Try and stop the thread
  uptr cmp = WaitQueue::kOpen;
  if (!atomic_compare_exchange_strong(
      &WaitQueue::slice_gate_[tid], &cmp, WaitQueue::kClosed, memory_order_relaxed)) {
    mtx.Unlock();
    return;
  }
  ++stat_reschedule_;
  Printf("Reschedule head: %llu slice: %llu\n", head_, slice_);
  WaitQueue::slice = WaitQueue::slice_length_; 
  ++tick_;
  atomic_fetch_add(&WaitQueue::queue_head, 1, memory_order_relaxed);
  mtx.Unlock();
  return;

/*  if (WaitQueue::slice_length_ < 2) {
    return;
  }
  // Realistically queue should never get here.
  static const u64 queue_ceiling = 0xFFFFFFFFFFFF0000ull;
  static u64 slice = 0;
  static u64 head = 0;
  mtx.Lock();
  u64 slice_ = WaitQueue::slice;
  u64 head_ = atomic_load(&WaitQueue::queue_head, memory_order_relaxed);
  if (slice_ == WaitQueue::slice_length_) {
    mtx.Unlock();
    return;
  }
  if (!(slice_ == slice && head_ == head)) {
    slice = slice_;
    head = head_;
    mtx.Unlock();
    return;
  }
  // This is still racy if the active tid has passed the queue check but not set
  // the active_tid.
  int tid = active_tid_;
  if (exclude_point_[tid] == 1) {
    mtx.Unlock();
    return;
  }
  CHECK(tid != -1 && "Oops!");
  // Also not good because of relaxed.
  if (atomic_load(&cond_vars_[tid], memory_order_relaxed) == kCritical) {
    mtx.Unlock();
    return;
  }
  ++stat_reschedule_;
  Printf("Reschedule head: %llu slice: %llu\n", head_, slice_);
  u64 queue_save = atomic_exchange(&WaitQueue::queue_head, queue_ceiling, memory_order_relaxed);
  WaitQueue::slice = WaitQueue::slice_length_;
  WaitQueue::demo_play_queue_pos_[tid] = 0; // Also gross
  active_tid_ = -1;
  ++tick_;
  CHECK(atomic_exchange(&WaitQueue::queue_head, queue_save + 1, memory_order_relaxed) == queue_ceiling);
  mtx.Unlock();
  return;*/
}

void Scheduler::Enable(int tid) {
  thread_status_[tid] = RUNNING;
  atomic_store(&WaitQueue::enabled[tid], WaitQueue::kEnabled, memory_order_relaxed);
}

void Scheduler::Disable(int tid) {
  thread_status_[tid] = DISABLED;
  atomic_store(&WaitQueue::enabled[tid], WaitQueue::kDisabled, memory_order_relaxed);
}

void WaitQueue::DemoPlayNext(int tid) {
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

void WaitQueue::DemoRecordNext(ThreadState *thr, u64 tick, u64 pos) {
  if (record_fd_ == kInvalidFd) {
    return;
  }
  //char line[33];

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

void WaitQueue::DemoRecordLine(char *buf, int tid, u64 pos) {
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

void WaitQueue::DemoRecordRepeat(char *buf, int tid, u64 count) {
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

//TODO SignalReceive()
// how does this work with kActive.
