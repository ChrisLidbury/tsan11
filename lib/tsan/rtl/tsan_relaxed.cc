// TODO Do not commit load when a release has happened until the load reads later
//      in mo.
// TODO Put latest store in buffer instead of treating it specially.

#include "tsan_relaxed.h"

#include "tsan_clock.h"
#include "tsan_rtl.h"
#include "tsan_schedule.h"
#include "sanitizer_common/sanitizer_placement_new.h"

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
                : "%rcx", "%rdx", "memory"); // rcx and rdx are clobbered
                                             // memory to prevent reordering
  return ret;
}

StoreBuffer::StoreBuffer() {
  Reset(0);
}

void StoreBuffer::Reset(Processor *proc) {
  last_pos_ = 0;
  size_ = 0;
  prev_tid_ = 0;
  prev_is_sc_access_ = false;
  prev_epoch_ = 0;
  //internal_memset(pos_, 0, sizeof(*pos_));
  //internal_memset(loads_, 0, sizeof(*loads_));
  internal_memset(pos_, 0, sizeof(pos_));
  internal_memset(loads_, 0, sizeof(loads_));
  if (proc == 0) {
    CHECK_EQ(stores_, 0);
    CHECK_EQ(stores_back_, 0);
    CHECK_EQ(prev_loads_, 0);
    return;
  }
  StoreElem *current = stores_;
  while (current != 0) {
    LoadElem *load = current->loads_;
    while (load != 0) {
      LoadElem *next = load->next_;
      ctx->load_alloc.Free(&proc->load_cache, load->id_);
      load = next;
    }
    StoreElem *next = current->next_;
    current->clock_.Reset(&proc->clock_cache, 0);
    ctx->store_alloc.Free(&proc->store_cache, current->id_);
    current = next;
  }
  stores_ = 0;
  stores_back_ = 0;
  LoadElem *load = prev_loads_;
  while (load != 0) {
    LoadElem *next = load->next_;
    ctx->load_alloc.Free(&proc->load_cache, load->id_);
    load = next;
  }
  prev_loads_ = 0;
}

void StoreBuffer::RemoveLoadFromList(LoadElem *load) {
  if (load->next_ != 0)
    load->next_->prev_ = load->prev_;
  if (load->prev_ != 0) {
    load->prev_->next_ = load->next_;
  } else {
    if (load->store_ != 0) {
      load->store_->loads_ = load->next_;
    } else {
      prev_loads_ = load->next_;
    }
  }
}

void StoreBuffer::AddLoadToList(LoadElem *load, StoreElem *store) {
  load->store_ = store;
  load->prev_ = 0;
  if (store != 0) {
    load->next_ = store->loads_;
    store->loads_ = load;
  } else {
    load->next_ = prev_loads_;
    prev_loads_ = load;
  }
  if (load->next_ != 0)
    load->next_->prev_ = load;
}

void StoreBuffer::BufferStore(ThreadState *thr, u64 bits, SyncClock *clock,
                              bool is_sc_access, bool is_release) {
  StoreElem *elem = 0;
  if (!stores_) {
    StatInc(thr, StatUniqueStore);
  }
  // Cap the buffer size, otherwise it will grow very large.
  if (stores_ && last_pos_ - stores_->pos_ > kBuffMaxSize) {
    // Remove elem from the front, free clock and loads.
    StatInc(thr, StatStoreElemFall);
    elem = stores_;
    stores_ = stores_->next_;
    if (stores_ != 0)
      stores_->prev_ = 0;
    for (LoadElem *load = elem->loads_; load != 0;) {
      StatInc(thr, StatLoadElemFall);
      if (loads_[load->tid_] == load)
        loads_[load->tid_] = 0;
      LoadElem *next = load->next_;
      ctx->load_alloc.Free(&thr->proc()->load_cache, load->id_);
      load = next;
    }
    elem->clock_.Reset(&thr->proc()->clock_cache, 0);
  } else {
    // Otherwise, allocate new elem.
    StatInc(thr, StatStoreElemCreate);
    u32 id = ctx->store_alloc.Alloc(&thr->proc()->store_cache);
    elem = ctx->store_alloc.Map(id);
    elem->id_ = id;
  }

  // Set up the StoreElem for the previous store.
  elem->pos_ = ++last_pos_;
  elem->epoch_ = prev_epoch_;
  clock->CopyClock(
      &thr->proc()->clock_cache, &thr->proc()->vclock_cache, &elem->clock_);
  elem->tid_ = prev_tid_;
  elem->is_sc_access_ = prev_is_sc_access_;
  elem->value_ = bits;
  elem->loads_ = prev_loads_;
  for (LoadElem *load = prev_loads_; load != 0; load = load->next_)
    load->store_ = elem;
  if (stores_ == 0) {
    stores_ = elem;
    elem->prev_ = 0;
  } else {
    stores_back_->next_ = elem;
    elem->prev_ = stores_back_;
  }
  stores_back_ = elem;
  elem->next_ = 0;
  // Threads pos in mo is now the front. This assumes the thread is about to
  // perform a store.
  pos_[thr->tid] = last_pos_ + 1;
  // Store this thread's info for the next buffer store.
  prev_epoch_ = thr->fast_state.epoch();
  prev_is_sc_access_ = is_sc_access;
  prev_tid_ = thr->tid;
  prev_loads_ = 0;

  // For SC stores, very inefficient, but no better solution right now.
  // Mark every store that happens before this as SC, when fetch store is called
  // for SC read, it will skip over these.
  if (is_sc_access)
    for (StoreElem *current = stores_back_; current != 0; current = current->prev_) {
      if (thr->clock.get(current->tid_) >= current->epoch_)
        current->is_sc_access_ = true;
    }

  // If there was a release by tid on some other var, commit immediately.
  if (loads_[thr->tid] && thr->last_release > loads_[thr->tid]->epoch_)
    loads_[thr->tid] = 0;
  // Signal all other vars to commit the load for this thread.
  if (is_release)
    thr->last_release = thr->fast_state.epoch();
  // No load needs to be stored, as if another thread synchronises on a later
  // store through another var, the acquiring thread's VC for this thread will
  // be later than the current epoch.
  if (loads_[thr->tid] != 0) {
    StatInc(thr, StatLoadElemDelete);
    LoadElem *load = loads_[thr->tid];
    RemoveLoadFromList(load);
    ctx->load_alloc.Free(&thr->proc()->load_cache, load->id_);
    loads_[thr->tid] = 0;
  }
}

bool StoreBuffer::FetchStore(ThreadState *thr, u64 *val, SyncClock **clock,
                             bool is_sc_access, bool is_release) {
  if (stores_ == 0)
    return false;

  // If current active load at the end, break out early.
  if (loads_[thr->tid] && loads_[thr->tid]->store_ == 0) {
    CHECK_EQ(pos_[thr->tid], last_pos_ + 1);
    return false;
  }
  // If there was a release by tid on some other var, commit immediately.
  if (loads_[thr->tid] && thr->last_release > loads_[thr->tid]->epoch_)
    loads_[thr->tid] = 0;
  // Set up a load to be attached to a store. This will either be removed from
  // the current active, or newly created.
  LoadElem *load = loads_[thr->tid];
  if (load == 0) {
    StatInc(thr, StatLoadElemCreate);
    u32 id = ctx->load_alloc.Alloc(&thr->proc()->load_cache);
    load = ctx->load_alloc.Map(id);
    load->id_ = id;
    load->tid_ = thr->tid;
    loads_[thr->tid] = load;
  } else {
    StatInc(thr, StatLoadElemMove);
    RemoveLoadFromList(load);
  }
  load->epoch_ = thr->fast_state.epoch();

  // If the latest write in mo happens before this, or SC fences only allow the
  // last write to be read, then set pos to end.
  if (thr->clock.get(prev_tid_) >= prev_epoch_ ||
      // Duplicate SC fence cases from the loop.
      (thr->Slimit.size() > prev_tid_ &&
          thr->Slimit.get(prev_tid_) >= prev_epoch_) ||
      (thr->Swrite.size() > prev_tid_ && prev_is_sc_access_ &&
          thr->Swrite.get(prev_tid_) >= prev_epoch_) ||
      (thr->Sread.size() > prev_tid_ && is_sc_access &&
          thr->Sread.get(prev_tid_) >= prev_epoch_)) {
    pos_[thr->tid] = last_pos_ + 1;
    AddLoadToList(load, 0);
    return false;
  }
  // If there is a load on the end of mo that has happens before this, set pos
  // to end.
  for (LoadElem *cur = prev_loads_; cur != 0; cur = cur->next_)
    if (thr->clock.get(cur->tid_) > cur->epoch_) {
      pos_[thr->tid] = last_pos_ + 1;
      AddLoadToList(load, 0);
      return false;
    }

  // Used if this is an SC write. Must identify last SC write and not read from
  // any other SC write. If the end is SC, use magic pointer but never deref.
  StoreElem *last_sc_store = 0;
  if (prev_is_sc_access_)
    last_sc_store = (StoreElem *)0x1;

  // Search backwards in mo for the earliest possible write to read from.
  StoreElem *limit = 0;
  for (StoreElem *current = stores_back_; current != 0; current = current->prev_) {
    // If the position in mo is earlier then this tid's pos, then we reached the
    // limit previously.
    if (pos_[thr->tid] > current->pos_)
      break;
    // Set last SC write if not yet found.
    if (last_sc_store == 0 && current->is_sc_access_)
      last_sc_store = current;
    // If the VC epoch for the storing thread shows the store has happened
    // before, then this is as far back as coherence of write-read allows.
    if (thr->clock.get(current->tid_) >= current->epoch_) {
      limit = current;
      break;
    }
    // If there is a hard limit caused by 2 SC fences.
    // If this is an SC store and this thread since did an SC fence.
    // If storing thread followed with an SC fence and this is an SC read.
    if ((thr->Slimit.size() > current->tid_ &&
            thr->Slimit.get(current->tid_) >= current->epoch_) ||
        (thr->Swrite.size() > current->tid_ && current->is_sc_access_ &&
            thr->Swrite.get(current->tid_) >= current->epoch_) ||
        (thr->Sread.size() > current->tid_ && is_sc_access &&
            thr->Sread.get(current->tid_) >= current->epoch_)) {
      limit = current;
      break;
    }
    // Search through the load buffer attached to this store for a load that has
    // happened before this load.
    LoadElem *load = 0;
    for (LoadElem *cur = current->loads_; cur != 0; cur = cur->next_)
      if (thr->clock.get(cur->tid_) > cur->epoch_) {
        load = cur;
        break;
      }
    if (load != 0) {
      limit = current;
      break;
    }
    // Nothing found, but set the limit in case this is the limit, but only
    // found on next iteration, or the end is reached.
    limit = current;
  }

  // limit points to the earliest store tis can read, or 0, if it cannot read
  // from the buffer.
  // Any adversarial memory strategy should go here.
  // For now, just read the earliest (+0 with 50% prob, +1 with 25%, ...).
  while (limit != 0 &&
         ((is_sc_access && limit->is_sc_access_ && limit != last_sc_store) ||
//         (rdtsc() & 4)))
         (ctx->scheduler.RandomNext(thr) & 1)))
    limit = limit->next_;
  if (limit == 0) {
    pos_[thr->tid] = last_pos_ + 1;
    AddLoadToList(load, 0);
    return false;
  }
  *val = limit->value_;
  *clock = &limit->clock_;
  pos_[thr->tid] = limit->pos_;
  AddLoadToList(load, limit);
  return true;
}

void StoreBuffer::AdvanceToEnd(ThreadState *thr) {
  pos_[thr->tid] = last_pos_ + 1;
  // Must move active load to the end, or create new load at end.
  // Quick exit if load already at the end.
  LoadElem *load = loads_[thr->tid];
  if (load != 0 && load->store_ == 0)
    return;
  // If there was a release by tid on some other var, commit immediately.
  if (load != 0 && thr->last_release > load->epoch_) {
    loads_[thr->tid] = 0;
    load = 0;
  }
  // Take current active or create new one.
  if (load == 0) {
    StatInc(thr, StatLoadElemCreate);
    u32 id = ctx->load_alloc.Alloc(&thr->proc()->load_cache);
    load = ctx->load_alloc.Map(id);
    load->id_ = id;
    load->tid_ = thr->tid;
    loads_[thr->tid] = load;
  } else {
    StatInc(thr, StatLoadElemMove);
    RemoveLoadFromList(load);
  }
  load->epoch_ = thr->fast_state.epoch();
  AddLoadToList(load, 0);
}

void StoreBuffer::FlushStores(ThreadState *thr) {

}

}  // namespace __tsan
