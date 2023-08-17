#ifndef __RS3_SOLVER_H__
#define __RS3_SOLVER_H__

#include "../include/rs3.h"

#define SOLVER_TIMEOUT_SEC (60 * 60) // 1 hour

typedef struct {
  int *pid;
  int *rpipe;
  int *wpipe;
} comm_t;

typedef void (*RS3_worker)(RS3_cfg_t, RS3_cnstrs_func);

#endif
