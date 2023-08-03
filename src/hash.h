#ifndef __RS3_HASH_H__
#define __RS3_HASH_H__

#include "../include/rs3.h"

#define STATS                   100000
#define DIST_THRESHOLD          0.1

typedef unsigned packet_fields_t;

RS3_key_hash_in_t RS3_packet_to_hash_input(RS3_loaded_opt_t opt, RS3_packet_t h);
RS3_packet_t      RS3_key_hash_in_to_packet(RS3_cfg_t cfg, RS3_loaded_opt_t opt, RS3_key_hash_in_t hi);
void              RS3_key_rand(RS3_cfg_t cfg, out RS3_key_t key);
void              RS3_zero_key(RS3_key_t key);
bool              RS3_is_zero_key(RS3_key_t key);

#endif
