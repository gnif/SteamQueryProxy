#include "challenge.h"
#include "util.h"

#include <stdlib.h>

// retain 60s worth of challenges
static uint32_t  g_challenges[6]  = { 0 };
static int       g_challengeIndex = 0;
static const int g_nChallenges    = sizeof(g_challenges) / sizeof(*g_challenges);

void challenge_init(void)
{
  for(int i = 0; i < g_nChallenges; ++i)
    challenge_new();
}

void challenge_new(void)
{
  int next = g_challengeIndex - 1;
  if (next < 0)
    next = g_nChallenges - 1;

  do
  {
    uint32_t new = jenkinsHash(rand() % UINT32_MAX);
    if (new == 0 || new == 0xFFFFFFFF)
      continue;

    g_challenges[next] = new;
    g_challengeIndex   = next;
    return;
  }
  while(false);
}

bool challenge_validate(uint32_t challenge, uint32_t mutate)
{
  if (challenge == 0 || challenge == 0xFFFFFFFF)
    return false;

  int index = g_challengeIndex;
  for(int i = 0; i < g_nChallenges; ++i)
  {
    const uint32_t check = g_challenges[index] + jenkinsHash(mutate);
    if (check == challenge)
      return true;

    if (++index == g_nChallenges)
      index = 0;
  }

  return false;
}

uint32_t challenge_get(uint32_t mutate)
{
  return g_challenges[g_challengeIndex] + jenkinsHash(mutate);
}
