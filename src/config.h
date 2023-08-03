#ifndef __RS3_CONFIG_H__
#define __RS3_CONFIG_H__

#include "../include/rs3.h"

RS3_status_t RS3_cfg_load_pf(out RS3_cfg_t cfg, unsigned iopt, RS3_pf_t pf);
RS3_status_t RS3_loaded_opt_check_pf(RS3_loaded_opt_t loaded_opt, RS3_pf_t pf);
unsigned     RS3_cfg_max_in_sz(RS3_cfg_t cfg);
RS3_status_t RS3_opt_to_pfs(RS3_opt_t opt, RS3_pf_t **pfs, unsigned *n_pfs);
bool         RS3_cfg_are_compatible_pfs(RS3_cfg_t cfg, RS3_in_cfg_t pfs);

#endif
