// For queue scheduling.
// Include in the scheduler and comment out other functions with same name lol.

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
  }
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
  if (flags()->record_demo && flags()->record_demo[0]) {
    char buf[128];
    internal_snprintf(buf, 128, "%s/%d-queue", flags()->record_demo, 0);
    record_fd_ = OpenFile(buf, WrOnly);
    for (int idx = 0; idx < 80; ++idx) {
      demo_record_file_pos_[idx] = internal_lseek(record_fd_, 0, SEEK_CUR);
      char line[65];
      DemoRecordLine(line, idx, -1);
      WriteToFile(record_fd_, line, /*64*/12);
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
  u64 pos = WaitQueue::demo_play_queue_pos_[thr->tid] == 0 ?
      atomic_fetch_add(&WaitQueue::queue_tail, 1, memory_order_relaxed) :
      WaitQueue::demo_play_queue_pos_[thr->tid];
  u64 cmp = pos;
  while (!atomic_compare_exchange_strong(
      &WaitQueue::queue_head, &cmp, pos, memory_order_relaxed)) {
    cmp = pos;
    proc_yield(20);
  }
  atomic_store(&cond_vars_[thr->tid], kCritical, memory_order_relaxed);
}

void Scheduler::Tick(ThreadState *thr) {
  mtx.Lock();
  uptr cmp = kCritical;
  bool is_critical = atomic_compare_exchange_strong(
      &cond_vars_[thr->tid], &cmp, kInactive, memory_order_relaxed);
  CHECK(is_critical);
  if (exclude_point_[thr->tid] == 1 && thread_status_[thr->tid] != DISABLED) {
    mtx.Unlock();
    return;
  }
  SignalPending(thr);
  u64 pos = atomic_fetch_add(&WaitQueue::queue_head, 1, memory_order_relaxed);
  WaitQueue::DemoRecordNext(thr, tick_, pos);
  WaitQueue::DemoPlayNext(thr->tid);
  ++tick_;
  {  // DEBUG
  //  Printf("%d - %d - ", thr->tid, pos);
  //  PrintUserSanitizerStackBoundary();
  //  Printf("\n");
  }
  mtx.Unlock();
  ProcessPendingSignals(thr);
  // If this was excluded, it must exit and reenter.
  if (exclude_point_[thr->tid] == 1) {
    exclude_point_[thr->tid] = 0;
    Wait(thr);
    exclude_point_[thr->tid] = 1;
  }
}

void Scheduler::Reschedule() {
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
    demo_contents_ += (12 - sizeof(int) - sizeof(u32));
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
  demo_contents_ += (12 - sizeof(int) - sizeof(u32));
}

void WaitQueue::DemoRecordNext(ThreadState *thr, u64 tick, u64 pos) {
  if (record_fd_ == kInvalidFd) {
    return;
  }
  char line[33];

  // History compacting for repeating threads.
  // First see if a previous repeat needs to be stored.
  if (demo_record_last_tid_ != thr->tid && demo_record_last_pos_ != (u64)-1) {
    uptr restore = internal_lseek(record_fd_, 0, SEEK_CUR);
    internal_lseek(record_fd_, demo_record_last_pos_, SEEK_SET);
    DemoRecordRepeat(line, demo_record_last_tid_, atomic_load(&queue_head, memory_order_relaxed) - 1);
    WriteToFile(record_fd_, line, 12);
    demo_record_last_pos_ = (u64)-1;
    internal_lseek(WaitQueue::record_fd_, restore, SEEK_SET);
  }
  // Now see if we are repeating.
  if (demo_record_last_tid_ == thr->tid) {
    // Are there already repeat line reserved in the demo file?
    if (demo_record_last_pos_ != (u64)-1) {
      return;
    }
    // No? Write "re -1", marking the position for another thread to overwrite.
    demo_record_last_pos_ = internal_lseek(record_fd_, 0, SEEK_CUR);
    DemoRecordRepeat(line, demo_record_last_tid_, (u64)-1);
    WriteToFile(record_fd_, line, 12);
  } else {
    // First consecutive write. Fall through and do the usual.
    demo_record_last_tid_ = thr->tid;
  }

  // Save current signal file pos and move to previously saved point.
  uptr restore = internal_lseek(WaitQueue::record_fd_, 0, SEEK_CUR);
  internal_lseek(WaitQueue::record_fd_,
      WaitQueue::demo_record_file_pos_[thr->tid], SEEK_SET);
  // Write the previous entry.
  DemoRecordLine(line, thr->tid, pos);
  WriteToFile(record_fd_, line, 12);
  // Go back to original position and reserve spot.
  internal_lseek(WaitQueue::record_fd_, restore, SEEK_SET);
  WaitQueue::demo_record_file_pos_[thr->tid] = restore;
  DemoRecordLine(line, thr->tid, -1);
  WriteToFile(WaitQueue::record_fd_, line, 12);
}

/*void WaitQueue::DemoRecordLine(char *buf, int tid, u64 pos) {
  static const int kLineLength = 12;
  u32 pos_ = pos;
  int written = internal_snprintf(buf, kLineLength + 1, "%d %u", tid, pos_);
  CHECK(written <= kLineLength);
  internal_memset(&buf[written], ' ', kLineLength - written - 1);
  buf[kLineLength - 1] = '\n';
  buf[kLineLength] = '\0';
}*/

void WaitQueue::DemoRecordLine(char *buf, int tid, u64 pos) {
  static const int kLineLength = 12;
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

/*void WaitQueue::DemoRecordRepeat(char *buf, int tid, u64 count) {
  static const int kLineLength = 12;
  u32 count_ = count;
  int written = internal_snprintf(buf, kLineLength + 1, "re %u", count_);
  CHECK(written <= kLineLength);
  internal_memset(&buf[written], ' ', kLineLength - written - 1);
  buf[kLineLength - 1] = '\n';
  buf[kLineLength] = '\0';
}*/

void WaitQueue::DemoRecordRepeat(char *buf, int tid, u64 count) {
  static const int kLineLength = 12;
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
