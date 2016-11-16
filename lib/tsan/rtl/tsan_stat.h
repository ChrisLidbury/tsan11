//===-- tsan_stat.h ---------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
//===----------------------------------------------------------------------===//

#ifndef TSAN_STAT_H
#define TSAN_STAT_H

namespace __tsan {

#define STATCROSS(t) \
  StatAtomic##t##Relaxed, \
  StatAtomic##t##Consume, \
  StatAtomic##t##Acquire, \
  StatAtomic##t##Release, \
  StatAtomic##t##Acq_Rel, \
  StatAtomic##t##Seq_Cst

enum StatType {
  // Memory access processing related stuff.
  StatMop,
  StatMopRead,
  StatMopWrite,
  StatMop1,  // These must be consequtive.
  StatMop2,
  StatMop4,
  StatMop8,
  StatMopSame,
  StatMopIgnored,
  StatMopRange,
  StatMopRodata,
  StatMopRangeRodata,
  StatShadowProcessed,
  StatShadowZero,
  StatShadowNonZero,  // Derived.
  StatShadowSameSize,
  StatShadowIntersect,
  StatShadowNotIntersect,
  StatShadowSameThread,
  StatShadowAnotherThread,
  StatShadowReplace,

  // Func processing.
  StatFuncEnter,
  StatFuncExit,

  // Trace processing.
  StatEvents,

  // Threads.
  StatThreadCreate,
  StatThreadFinish,
  StatThreadReuse,
  StatThreadMaxTid,
  StatThreadMaxAlive,

  // Mutexes.
  StatMutexCreate,
  StatMutexDestroy,
  StatMutexLock,
  StatMutexUnlock,
  StatMutexRecLock,
  StatMutexRecUnlock,
  StatMutexReadLock,
  StatMutexReadUnlock,

  // Synchronization.
  StatSyncCreated,
  StatSyncDestroyed,
  StatSyncAcquire,
  StatSyncRelease,

  // Clocks - acquire.
  StatClockAcquire,
  StatClockAcquireEmpty,
  StatClockAcquireFastRelease,
  StatClockAcquireLarge,
  StatClockAcquireRepeat,
  StatClockAcquireFull,
  StatClockAcquiredSomething,
  // Clocks - release.
  StatClockRelease,
  StatClockReleaseResize,
  StatClockReleaseFast1,
  StatClockReleaseFast2,
  StatClockReleaseSlow,
  StatClockReleaseFull,
  StatClockReleaseAcquired,
  StatClockReleaseClearTail,
  // Clocks - release store.
  StatClockStore,
  StatClockStoreResize,
  StatClockStoreFast,
  StatClockStoreFull,
  StatClockStoreTail,
  // Clocks - acquire-release.
  StatClockAcquireRelease,

  // tsan11
  StatTsan11,
  StatVVC,
  StatInitVVC,
  StatAddToVVC,
  StatModifyVVC,
  StatCollapseVVC,
  StatRelaxed,
  StatStoreElemCreate,
  StatStoreElemFall,
  StatLoadElemCreate,
  StatLoadElemMove,
  StatLoadElemFall,
  StatLoadElemDelete,
  StatUniqueStore,

  // Atomics.
  StatAtomic,
  StatAtomicLoad,
  StatAtomicStore,
  StatAtomicExchange,
  StatAtomicFetchAdd,
  StatAtomicFetchSub,
  StatAtomicFetchAnd,
  StatAtomicFetchOr,
  StatAtomicFetchXor,
  StatAtomicFetchNand,
  StatAtomicCAS,
  StatAtomicFence,
  StatAtomicRelaxed,
  StatAtomicConsume,
  StatAtomicAcquire,
  StatAtomicRelease,
  StatAtomicAcq_Rel,
  StatAtomicSeq_Cst,
  StatAtomic1,
  StatAtomic2,
  StatAtomic4,
  StatAtomic8,
  StatAtomic16,

  // Atomic combinations.
  STATCROSS(Load),
  STATCROSS(Store),
  STATCROSS(Exchange),
  STATCROSS(FetchAdd),
  STATCROSS(FetchSub),
  STATCROSS(FetchAnd),
  STATCROSS(FetchOr),
  STATCROSS(FetchXor),
  STATCROSS(FetchNand),
  STATCROSS(CAS),
  STATCROSS(Fence),

  // Dynamic annotations.
  StatAnnotation,
  StatAnnotateHappensBefore,
  StatAnnotateHappensAfter,
  StatAnnotateCondVarSignal,
  StatAnnotateCondVarSignalAll,
  StatAnnotateMutexIsNotPHB,
  StatAnnotateCondVarWait,
  StatAnnotateRWLockCreate,
  StatAnnotateRWLockCreateStatic,
  StatAnnotateRWLockDestroy,
  StatAnnotateRWLockAcquired,
  StatAnnotateRWLockReleased,
  StatAnnotateTraceMemory,
  StatAnnotateFlushState,
  StatAnnotateNewMemory,
  StatAnnotateNoOp,
  StatAnnotateFlushExpectedRaces,
  StatAnnotateEnableRaceDetection,
  StatAnnotateMutexIsUsedAsCondVar,
  StatAnnotatePCQGet,
  StatAnnotatePCQPut,
  StatAnnotatePCQDestroy,
  StatAnnotatePCQCreate,
  StatAnnotateExpectRace,
  StatAnnotateBenignRaceSized,
  StatAnnotateBenignRace,
  StatAnnotateIgnoreReadsBegin,
  StatAnnotateIgnoreReadsEnd,
  StatAnnotateIgnoreWritesBegin,
  StatAnnotateIgnoreWritesEnd,
  StatAnnotateIgnoreSyncBegin,
  StatAnnotateIgnoreSyncEnd,
  StatAnnotatePublishMemoryRange,
  StatAnnotateUnpublishMemoryRange,
  StatAnnotateThreadName,

  // Internal mutex contentionz.
  StatMtxTotal,
  StatMtxTrace,
  StatMtxThreads,
  StatMtxReport,
  StatMtxSyncVar,
  StatMtxSyncTab,
  StatMtxSlab,
  StatMtxAnnotations,
  StatMtxAtExit,
  StatMtxMBlock,
  StatMtxDeadlockDetector,
  StatMtxFired,
  StatMtxRacy,
  StatMtxFD,
  StatMtxSC,
  StatMtxScheduler,
  StatMtxGlobalProc,

  // This must be the last.
  StatCnt
};

#undef STATCROSS

}  // namespace __tsan

#endif  // TSAN_STAT_H
