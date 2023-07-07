#include <stdatomic.h>

typedef atomic_flag Lock;

#define LOCK(x) \
  while(atomic_flag_test_and_set_explicit(&(x), memory_order_acquire)) { ; }
#define UNLOCK(x) \
  atomic_flag_clear_explicit(&(x), memory_order_release);
