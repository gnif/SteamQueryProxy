#ifndef _H_LOCKING_
#define _H_LOCKING_

#include <stdatomic.h>

typedef atomic_flag Lock;

#define LOCK(x) \
  while(atomic_flag_test_and_set_explicit(&(x), memory_order_acquire)) { ; }
#define UNLOCK(x) \
  atomic_flag_clear_explicit(&(x), memory_order_release);

typedef struct
{
  atomic_int  readCounter;
  atomic_bool writeLockRequested;
  atomic_flag writeLock;
}
RWLock;

static inline void rwlock_init(RWLock * lock)
{
  lock->readCounter        = ATOMIC_VAR_INIT(0);
  lock->writeLockRequested = ATOMIC_VAR_INIT(false);
  atomic_flag_clear_explicit(&lock->writeLock, memory_order_release);
}

static inline void rwlock_readLock(RWLock * lock)
{
  for(;;)
  {
    while (atomic_load_explicit(&lock->writeLockRequested,
      memory_order_acquire)) { ; }

    atomic_fetch_add_explicit(&lock->readCounter, 1, memory_order_acquire);
    if (!atomic_load_explicit(&lock->writeLockRequested, memory_order_acquire))
      break;

    atomic_fetch_sub_explicit(&lock->readCounter, 1, memory_order_release);
  }
}

static inline void rwlock_readUnlock(RWLock * lock)
{
  atomic_fetch_sub_explicit(&lock->readCounter, 1, memory_order_release);
}

static inline void rwlock_writeLock(RWLock * lock)
{
  atomic_store_explicit(&lock->writeLockRequested, true, memory_order_relaxed);
  while (atomic_load_explicit(&lock->readCounter,
    memory_order_acquire) > 0) { ; }
  while (atomic_flag_test_and_set_explicit(&lock->writeLock,
    memory_order_acquire)) { ; }
}

static inline void rwlock_writeUnlock(RWLock * lock)
{
  atomic_store_explicit(&lock->writeLockRequested, false, memory_order_relaxed);
  atomic_flag_clear_explicit(&lock->writeLock, memory_order_release);
}

#endif
