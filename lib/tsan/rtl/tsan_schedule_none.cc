// No strategy.

#include "tsan_schedule.h"

#include "tsan_rtl.h"

namespace __tsan {

void Scheduler::StrategyNoneInitialise() {
  WaitFunc       = &Scheduler::StrategyNoneWait;
  TickFunc       = &Scheduler::StrategyNoneTick;
  EnableFunc     = &Scheduler::StrategyNoneEnable;
  DisableFunc    = &Scheduler::StrategyNoneDisable;
  RescheduleFunc = &Scheduler::StrategyNoneReschedule;
  SignalWakeFunc = &Scheduler::StrategyNoneSignalWake;
  CHECK((!flags()->play_demo   || !flags()->play_demo[0]  ) &&
        (!flags()->record_demo || !flags()->record_demo[0]) &&
      "Cannot use demos with no scheduler strategy.");
}

void Scheduler::StrategyNoneWait(ThreadState *thr) {
  return;
}

void Scheduler::StrategyNoneTick(ThreadState *thr) {
  return;
}

void Scheduler::StrategyNoneEnable(int tid) {
  return;
}

void Scheduler::StrategyNoneDisable(int tid) {
  return;
}

void Scheduler::StrategyNoneReschedule() {
  return;
}

void Scheduler::StrategyNoneSignalWake(ThreadState *thr) {
  return;
}

}  // namespace __tsan
