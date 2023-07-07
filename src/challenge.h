#ifndef _H_CHALLENGE_
#define _H_CHALLENGE_

#include <stdbool.h>
#include <stdint.h>

void challenge_init(void);
void challenge_new(void);
bool challenge_validate(uint32_t challenge, uint32_t mutate);
uint32_t challenge_get(uint32_t mutate);

#endif
