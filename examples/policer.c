/*
 * Policer example.
 *
 * Policer is a network function responsible for controlling the bandwidth used
 *by clients,
 * which typically is associated with a contract.
 *
 * Each bandwidth is associated with a client's IP address, so packet counting
 *is made on
 * every packet routed to the client. This means that the network function keeps
 *a global
 * state associated with the destination IP of each incoming packet.
 *
 * In order to fully parallelize this network function, the packets with equal
 *destination
 * IP must be sent to the same core. This allows for access to shared data
 *structures
 * without the need to use locking mechanisms.
 *
 * This example provides the means to retrieve an RSS key that complies with
 *these
 * requirements, i.e., an RSS configuration (RSS key and configuration options)
 *that
 * sends packets with the same destination IP address to the same core.
 */

#include <rs3.h>
#include <stdio.h>
#include <stdlib.h>

Z3_ast mk_p_cnstrs(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2) {
  RS3_status_t status;

  if (p1.key_id == 0 && p2.key_id == 0) {
    Z3_ast p1_ipv4_dst;
    Z3_ast p2_ipv4_dst;
    Z3_ast eq_dst_ip;

    status = RS3_packet_extract_pf(cfg, p1, RS3_PF_IPV4_DST, &p1_ipv4_dst);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    status = RS3_packet_extract_pf(cfg, p2, RS3_PF_IPV4_DST, &p2_ipv4_dst);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    eq_dst_ip = Z3_mk_eq(cfg->ctx, p1_ipv4_dst, p2_ipv4_dst);

    return Z3_simplify(cfg->ctx, eq_dst_ip);
  }

  return NULL;
}

int validate(RS3_cfg_t cfg, RS3_key_t *keys, unsigned n_keys) {
  RS3_packet_t p1, p2;
  RS3_key_hash_out_t o1, o2;
  RS3_packet_from_cnstrs_data_t data;

  for (int ik = 0; ik < n_keys; ik++)
    for (int i = 0; i < 5; i++) {
      RS3_packet_rand(cfg, &p1);

      data.constraints = &mk_p_cnstrs;
      data.packet_in = p1;
      data.key_id_in = ik;
      data.key_id_out = ik;

      RS3_packet_from_cnstrs(cfg, data, &p2);

      RS3_key_hash(cfg, keys[ik], p1, &o1);
      RS3_key_hash(cfg, keys[ik], p2, &o2);

      printf("\n===== iteration %d =====\n", i);

      printf("%s\n", RS3_packet_to_string(p1));
      printf("hash: %s\n\n", RS3_key_hash_output_to_string(o1));

      printf("%s\n", RS3_packet_to_string(p2));
      printf("hash: %s\n\n", RS3_key_hash_output_to_string(o2));
      ;

      if (o1 != o2) {
        printf("Failed! %u != %u. Exiting.\n", o1, o2);
        return 0;
      }
    }

  return 1;
}

int main() {
  RS3_cfg_t cfg;
  RS3_key_t keys[2];
  RS3_opt_t *opts;
  size_t opts_sz;
  RS3_pf_t pfs[1] = { RS3_PF_IPV4_DST };

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 2);
  RS3_opts_from_pfs(pfs, 1, &opts, &opts_sz);
  RS3_cfg_set_skew_analysis(cfg, true);

  printf("Resulting options:\n");
  for (unsigned i = 0; i < opts_sz; i++) {
    printf("%s\n", RS3_opt_to_string(opts[i]));
    RS3_cfg_load_opt(cfg, opts[i]);
  }

  printf("\nConfiguration:\n%s\n", RS3_cfg_to_string(cfg));

  RS3_keys_fit_cnstrs(cfg, &mk_p_cnstrs, keys);

  printf("key 1:\n%s\n", RS3_key_to_string(keys[0]));
  printf("key 2:\n%s\n", RS3_key_to_string(keys[1]));

  validate(cfg, keys, 2);

  RS3_cfg_delete(cfg);

  free(opts);
}
