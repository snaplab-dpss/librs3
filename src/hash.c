#include "hash.h"
#include "config.h"
#include "packet.h"
#include "printer.h"
#include "util.h"

#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void RS3_key_rand(RS3_cfg_t cfg, RS3_key_t key) {
  init_rand();

  for (unsigned byte = 0; byte < KEY_SIZE; byte++) {
    key[byte] = rand() & 0xff;
  }
}

void RS3_key_only_ones(RS3_key_t key) {
  for (int byte = 0; byte < KEY_SIZE; byte++)
    key[byte] = 0xff;
}

void RS3_zero_key(RS3_key_t key) {
  for (int byte = 0; byte < KEY_SIZE; byte++)
    key[byte] = 0;
}

bool RS3_is_zero_key(RS3_key_t key) {
  for (int byte = 0; byte < KEY_SIZE; byte++)
    if (key[byte])
      return false;
  return true;
}

RS3_key_hash_in_t RS3_packet_to_hash_input(RS3_loaded_opt_t opt,
                                           RS3_packet_t p) {
  RS3_key_hash_in_t hi;
  unsigned sz, offset;
  RS3_byte_t *field;
  RS3_pf_t pf;

  hi = (RS3_key_hash_in_t)malloc(sizeof(RS3_byte_t) * (opt.sz / 8));
  offset = 0;
  sz = 0;

  for (int ipf = RS3_FIRST_PF; ipf <= RS3_LAST_PF; ipf++) {
    pf = (RS3_pf_t)ipf;

    if (RS3_loaded_opt_check_pf(opt, pf) != RS3_STATUS_PF_LOADED)
      continue;

    if (!RS3_packet_has_pf(p, pf))
      continue;

    field = RS3_packet_get_field(&p, pf);
    sz = RS3_pf_sz(pf);

    for (unsigned byte = 0; byte < sz; byte++, field++)
      hi[offset + byte] = *field;

    offset += sz;
  }

  return hi;
}

RS3_packet_t RS3_key_hash_in_to_packet(RS3_cfg_t cfg, RS3_loaded_opt_t opt,
                                       RS3_key_hash_in_t hi) {
  RS3_packet_t p;
  unsigned sz, offset;
  RS3_pf_t pf;

  RS3_packet_init(&p);

  offset = 0;

  // This requires the order of RS3_pf_t to be the order that each packet field
  // appears on a packet.
  for (int ipf = RS3_FIRST_PF; ipf <= RS3_LAST_PF; ipf++) {
    pf = (RS3_pf_t)ipf;

    if (RS3_loaded_opt_check_pf(opt, pf) != RS3_STATUS_PF_LOADED)
      continue;

    RS3_status_t status =
        RS3_packet_set_pf(cfg, pf, (RS3_bytes_t) & (hi[offset]), &p);
    assert(status == RS3_STATUS_SUCCESS);

    offset += RS3_pf_sz(pf);
  }

  return p;
}

void lshift(RS3_key_t k) {
  RS3_byte_t lsb, msb = 0; // there are no 1-bit data structures in C :(

  for (int i = KEY_SIZE; i >= 0; i--) {
    lsb = (k[i] >> 7) & 1;
    k[i] = ((k[i] << 1) | msb) & 0xff;
    msb = lsb;
  }

  k[KEY_SIZE - 1] |= msb;
}

RS3_status_t RS3_key_hash(RS3_cfg_t cfg, RS3_key_t k, RS3_packet_t p,
                          out RS3_key_hash_out_t *o) {
  RS3_key_t k_copy;
  RS3_key_hash_in_t hi;
  RS3_status_t status;
  RS3_loaded_opt_t loaded_opt;
  RS3_packet_ast_t packet_ast;

  status = RS3_packet_to_loaded_opt(cfg, p, &loaded_opt);

  if (status != RS3_STATUS_SUCCESS)
    return status;

  *o = 0;
  hi = RS3_packet_to_hash_input(loaded_opt, p);

  memcpy(k_copy, k, sizeof(RS3_byte_t) * KEY_SIZE);

  for (unsigned i = 0; i < loaded_opt.sz / 8; i++) {
    // iterate every bit
    for (int shift = 7; shift >= 0; shift--) {
      if ((hi[i] >> shift) & 1)
        *o ^= _32_LSB(k_copy);
      lshift(k_copy);
    }
  }

  free(hi);

  return RS3_STATUS_SUCCESS;
}
