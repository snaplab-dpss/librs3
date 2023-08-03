#ifndef __RS3_PACKET_H__
#define __RS3_PACKET_H__

#include "../include/rs3.h"
#include <stdbool.h>

#define RS3_pf_sz(pf)   (RS3_pf_sz_bits((pf)) < 1 ? 8 : RS3_pf_sz_bits((pf)) / 8)

size_t        RS3_pf_sz_bits(RS3_pf_t pf);
bool          RS3_packet_has_pf(RS3_packet_t p, RS3_pf_t pf);
RS3_bytes_t   RS3_packet_get_field(RS3_packet_t *p, RS3_pf_t pf);
RS3_status_t  RS3_packet_to_loaded_opt(RS3_cfg_t cfg, RS3_packet_t p, out RS3_loaded_opt_t *opt);

#endif