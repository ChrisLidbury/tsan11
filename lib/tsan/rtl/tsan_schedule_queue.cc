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

// Used by Tick() to direct the next Wait() to a queue position. Usually just
// used by the time slicing to keep the same queue position.
u64 direct_queue_pos_[Scheduler::kNumThreads];

// Allows asynchronous events (e.g. Reschedule()) to interrupt the scheduling.
// Threads can only clear Wait(), and events can only activate, if the gate is
// open; the gate is closed behind them.
static const int kOpen = 0;
static const int kClosed = 1;
atomic_uintptr_t wait_gate_[Scheduler::kNumThreads];

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

// Used to determine when a reschedule event should take place.
u64 reschedule_slice_;
u64 reschedule_head_;

// For BlockWait and BlockSignal. This may need to be a heap as I cannot
// guarantee there is no contention for each space.
atomic_uint32_t block_pos_[Scheduler::kNumThreads];

void QueueDemoPlayInitialise();
void QueueDemoPlayNext(int tid, u64 pos);
void QueueDemoRecordInitialise();
void QueueDemoRecordNext(int tid, u64 pos);
void QueueDemoRecordLine(char *buf, int tid, u64 pos);
void QueueDemoRecordRepeat(char *buf, int tid, u64 count);

// Initialise the demo play system specific to the queue strategy.
void QueueDemoPlayInitialise() {
  demo_play_queue_end_ = 0;
  // Open demo play file.
  if (flags()->play_demo && flags()->play_demo[0]) {
    uptr buffer_size;
    uptr contents_size;
    char buf[128];
    internal_snprintf(buf, 128, "%s/QUEUE", flags()->play_demo, 0);
    CHECK(ReadFileToBuffer(buf, &demo_contents_, &buffer_size, &contents_size));
    for (int idx = 0; idx < 80; ++idx) {
      QueueDemoPlayNext(idx, 0);
    }
  } else {
    demo_contents_ = nullptr;
    for (int idx = 0; idx < 80; ++idx) {
      demo_play_queue_pos_[idx] = 0;
    }
  }
  demo_play_last_tid_ = -1;
}

// Read the next queue position for the current thread from 'QUEUE'.
// The current file position will be right for this thread.
void QueueDemoPlayNext(int tid, u64 pos) {
  if (demo_contents_ == nullptr/* || demo_contents_[0] == '\0'*/) {
    return;
  }

  // First check if history is still valid.
  if (pos < demo_play_queue_end_) {
    CHECK(demo_play_last_tid_ == tid && "demo play error");
    demo_play_queue_pos_[tid] = pos;
    return;
  }
  // If not then check if there will be.
  if (demo_contents_[0] == 'r' && demo_contents_[1] == 'e') {
    demo_play_last_tid_ = tid;
    demo_contents_ += 4;
    u32 end;
    internal_memcpy(&end, demo_contents_, sizeof(u32));
    demo_contents_ += sizeof(u32);
    demo_play_queue_end_ = end;
    demo_contents_ += (kLineLength - sizeof(int) - sizeof(u32));
    demo_play_queue_pos_[tid] = pos;
    // Silly, If the repeat length is 0.
    if (pos < demo_play_queue_end_) {
      return;
    }
  }

  int tid_;
  internal_memcpy(&tid_, demo_contents_, sizeof(int));
  demo_contents_ += sizeof(int);
//  CHECK(tid_ == tid && "Demo play file has desynchronised.");
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
    internal_snprintf(buf, 128, "%s/QUEUE", flags()->record_demo, 0);
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
void QueueDemoRecordNext(int tid, u64 pos) {
  if (record_fd_ == kInvalidFd) {
    return;
  }

  // History compacting for repeating threads.
  // First see if a previous repeat needs to be stored.
  if (demo_record_last_tid_ != tid && demo_record_last_pos_ != (u64)-1) {
    demo_record_re_tid_[tid] = demo_record_last_tid_;
    demo_record_re_pos_[tid] = demo_record_last_pos_;
    demo_record_queue_[tid] = pos;
    demo_record_last_pos_ = (u64)-1;
  }
  // Now see if we are repeating.
  if (demo_record_last_tid_ == tid) {
    // Are there already repeat line reserved in the demo file?
    if (demo_record_last_pos_ != (u64)-1) {
      return;
    }
    // No? Write "re -1", marking the position for another thread to overwrite.
    demo_record_last_pos_ = foff;
    foff += kLineLength;
  } else {
    // First consecutive write. Fall through and do the usual.
    demo_record_last_tid_ = tid;
  }

  // Save current file pos.
  uptr restore = foff;
  foff += kLineLength;
  // Write the previous entry.
  demo_record_queue_[tid] = pos;
  demo_record_pos_[tid] = demo_record_file_pos_[tid];
  demo_record_file_pos_[tid] = restore;
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
  SignalWakeFunc = &Scheduler::StrategyQueueSignalWake;
  atomic_store(&queue_head, 1, memory_order_relaxed);
  atomic_store(&queue_tail, 1, memory_order_relaxed);
  atomic_store(&enabled[0], kEnabled, memory_order_relaxed);
  internal_memset(direct_queue_pos_, 0, sizeof(direct_queue_pos_));
  internal_memset(wait_gate_, kOpen, sizeof(wait_gate_));
  internal_memset(block_pos_, -1, sizeof(block_pos_));
  reschedule_slice_ = 0;
  reschedule_head_ = 0;
  QueueDemoPlayInitialise();
  QueueDemoRecordInitialise();
}

void Scheduler::StrategyQueueWait(ThreadState *thr) {
  if (exclude_point_[thr->tid] == 1) {
    return;
  }
  // Is thread blocked (e.g. mutex lock fail).
  /*uptr stat = kEnabled;
  while (!atomic_compare_exchange_strong(
      &enabled[thr->tid], &stat, kEnabled, memory_order_relaxed)) {
    stat = kEnabled;
    ProcessPendingSignals(thr);  // Dangerous, must change.
    proc_yield(20);
  }*/
  BlockWait(thr->tid, &enabled[thr->tid], kEnabled, kEnabled,
      !signal_context_[thr->tid]);

  // Get next position in queue. Precedence is direct > demo > queue.
  u64 pos;
  if (direct_queue_pos_[thr->tid] != 0) {
    // Continue time slice, unless rescheduled.
    pos = direct_queue_pos_[thr->tid];
    direct_queue_pos_[thr->tid] = 0;
    uptr cmp = kOpen;
    if (!atomic_compare_exchange_strong(
        &wait_gate_[thr->tid], &cmp, kClosed, memory_order_relaxed)) {
      // Reschedule()'d.
      atomic_store(&wait_gate_[thr->tid], kOpen, memory_order_relaxed);
      pos = atomic_fetch_add(&queue_tail, 1, memory_order_relaxed);
    }
  } else if (demo_play_queue_pos_[thr->tid] != 0) {
    // Read from demo file. Occurs at start of each slice.
    pos = demo_play_queue_pos_[thr->tid];
    atomic_fetch_add(&queue_tail, 1, memory_order_relaxed);
  } else {
    // No demo or slice, get to the back of the queue.
    pos = atomic_fetch_add(&queue_tail, 1, memory_order_relaxed);
  }

  // Has queue caught up yet.
  /*u64 cmp = pos;
  while (!atomic_compare_exchange_strong(
      &queue_head, &cmp, pos, memory_order_relaxed)) {
    CHECK(cmp <= pos && "Uh oh!");  // Only for reschedule
    cmp = pos;
    proc_yield(20);
  }*/
  atomic_store(&block_pos_[pos % kNumThreads], thr->tid, memory_order_seq_cst);
  BlockWait(thr->tid, (atomic_uintptr_t *)(&queue_head), pos, pos, false);  // dodgy cast
  atomic_store(&block_pos_[pos % kNumThreads], -1, memory_order_seq_cst);
}

void Scheduler::StrategyQueueTick(ThreadState *thr) {
  mtx.Lock();
  // DEBUG
  //Printf("%d - %d - ", thr->tid, tick_);
  //PrintUserSanitizerStackBoundary();
  //Printf("\n");
  // If annotated out, immediately reenable this thread.
  if (exclude_point_[thr->tid] == 1 && thread_status_[thr->tid] != DISABLED) {
    mtx.Unlock();
    return;
  }

  // Demo event checked first, there should be at most one reschedule.
  bool rescheduled = false;
  DemoPlayPeekNext();
  while (DemoPlayActive() && tick_ == demo_play_.demo_tick_) {
    if (demo_play_.event_type_ == RESCHEDULE) {
      CHECK(slice_ > 1 && "Stray RESCHEDULE.");
      CHECK(!rescheduled && "Multiple RESCHEDULE.");
      rescheduled = true;
    } else if (demo_play_.event_type_ == SIG_WAKEUP) {
      Enable(demo_play_.event_param_);
    } else {
      CHECK(false && "Unknown event type in replay.");
    }
    DemoRecordNext(tick_, demo_play_.event_type_, demo_play_.event_param_, 0);
    DemoPlayNext();
  }
  // Check for time slice.
  bool need_record = (slice_ == kSliceLength);
  u64 pos = 0;
  if (slice_ > 1 && thread_status_[thr->tid] == RUNNING && !rescheduled) {
    --slice_;
    pos = atomic_load(&queue_head, memory_order_relaxed);
    direct_queue_pos_[thr->tid] = pos;
    active_tid_ = thr->tid;
    atomic_store(&wait_gate_[thr->tid], kOpen, memory_order_relaxed);
  } else {
    slice_ = kSliceLength;
    // Careful with this, it will let the next thread return from Wait().
    pos = atomic_fetch_add(&queue_head, 1, memory_order_relaxed);
    unsigned signal_tid =
        atomic_load(&block_pos_[(pos + 1) % kNumThreads], memory_order_seq_cst);
    if (signal_tid != (u32)-1) {
      BlockSignal(signal_tid);
    }
    active_tid_ = -1;
  }
  CHECK((!need_record || pos != 0) && "Bad queue position");

  // Kinda hacky, but only record and replay at the start of each slice.
  if (need_record) {
    QueueDemoPlayNext(thr->tid, pos + 1);
    QueueDemoRecordNext(thr->tid, pos);
  }
  SignalPending(thr);
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

  ProcessPendingSignals(thr);
  // If this was excluded, it must exit and reenter.
  if (exclude_point_[thr->tid] == 1) {
    exclude_point_[thr->tid] = 0;
    Wait(thr);
    exclude_point_[thr->tid] = 1;
  }
}

void Scheduler::StrategyQueueEnable(int tid) {
  thread_status_[tid] = RUNNING;
  atomic_store(&enabled[tid], kEnabled, memory_order_relaxed);
  BlockSignal(tid);
}

void Scheduler::StrategyQueueDisable(int tid) {
  thread_status_[tid] = DISABLED;
  atomic_store(&enabled[tid], kDisabled, memory_order_relaxed);
}

void Scheduler::StrategyQueueReschedule() {
  if (kSliceLength < 2) {
    return;
  }
  mtx.Lock();
  if (DemoPlayActive() || exclude_point_[active_tid_] == 1) {
    mtx.Unlock();
    return;
  }

  u64 this_slice = slice_;
  u64 this_head = atomic_load(&queue_head, memory_order_relaxed);
  // Not in the middle of a slice.
  if (this_slice == kSliceLength) {
    mtx.Unlock();
    return;
  }
  // Have advanced since last Reschedule().
  if (!(this_slice == reschedule_slice_ && this_head == reschedule_head_)) {
    reschedule_slice_ = this_slice;
    reschedule_head_ = this_head;
    mtx.Unlock();
    return;
  }
  // active_tid_ is set to a tid if it is in the middle of a slice.
  int tid = active_tid_;
  if (exclude_point_[tid] == 1) {
    mtx.Unlock();
    return;
  }
  CHECK(tid != -1 && "Oops!");
  // Try and stop the thread
  uptr cmp = kOpen;
  if (!atomic_compare_exchange_strong(
      &wait_gate_[tid], &cmp, kClosed, memory_order_relaxed)) {
    mtx.Unlock();
    return;
  }
  // Pseudo tick.
  slice_ = kSliceLength;
  u64 pos = atomic_fetch_add(&queue_head, 1, memory_order_relaxed);
  unsigned signal_tid =
      atomic_load(&block_pos_[(pos + 1) % kNumThreads], memory_order_seq_cst);
  if (signal_tid != (u32)-1) {
    BlockSignal(signal_tid);
  }
  active_tid_ = -1;
  DemoRecordOverride(tick_ - 1, RESCHEDULE, 1, 0);
  mtx.Unlock();
}

void Scheduler::StrategyQueueSignalWake(ThreadState *thr) {
  mtx.Lock();
  if (DemoPlayActive() || thread_status_[thr->tid] != DISABLED) {
    mtx.Unlock();
    return;
  }
  Enable(thr->tid);
  DemoRecordNext(tick_ - 1, SIG_WAKEUP, thr->tid, 0);
  mtx.Unlock();
}

}  // namespace __tsan
