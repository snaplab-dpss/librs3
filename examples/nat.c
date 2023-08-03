#include <rs3.h>

Z3_ast mk_p_cnstrs(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2) {

  // independent constraints for each specific key
  if (p1.key_id == p2.key_id)
    return NULL;

  // LAN => WAN
  if (p1.key_id == 0 && p2.key_id == 1)
    return NULL;

  // WAN => LAN
  Z3_ast p1_l3_src;
  Z3_ast p2_l3_dst;

  Z3_ast p1_l4_src;
  Z3_ast p2_l4_dst;

  RS3_packet_extract_pf(cfg, p1, RS3_PF_IPV4_SRC, &p1_l3_src);
  RS3_packet_extract_pf(cfg, p2, RS3_PF_IPV4_DST, &p2_l3_dst);

  if (p1.loaded_opt.opt == RS3_OPT_NON_FRAG_IPV4_TCP) {
    RS3_packet_extract_pf(cfg, p1, RS3_PF_TCP_SRC, &p1_l4_src);
  } else if (p1.loaded_opt.opt == RS3_OPT_NON_FRAG_IPV4_UDP) {
    RS3_packet_extract_pf(cfg, p1, RS3_PF_UDP_SRC, &p1_l4_src);
  } else {
    return NULL;
  }

  if (p2.loaded_opt.opt == RS3_OPT_NON_FRAG_IPV4_TCP) {
    RS3_packet_extract_pf(cfg, p2, RS3_PF_TCP_DST, &p2_l4_dst);
  } else if (p2.loaded_opt.opt == RS3_OPT_NON_FRAG_IPV4_UDP) {
    RS3_packet_extract_pf(cfg, p2, RS3_PF_UDP_DST, &p2_l4_dst);
  } else {
    return NULL;
  }

  Z3_ast _and_args[2] = { Z3_mk_eq(cfg->ctx, p1_l3_src, p2_l3_dst),
                          Z3_mk_eq(cfg->ctx, p1_l4_src, p2_l4_dst) };

  Z3_ast final = Z3_simplify(cfg->ctx, Z3_mk_and(cfg->ctx, 2, _and_args));

  return final;
}

int validate(RS3_cfg_t cfg, RS3_key_t k1, RS3_key_t k2) {
  RS3_packet_t p12_1, p12_2;
  RS3_key_hash_out_t o12_1, o12_2;
  RS3_packet_from_cnstrs_data_t data;

  for (int i = 0; i < 5; i++) {
    RS3_packet_rand(cfg, &p12_1);

    data.constraints = &mk_p_cnstrs;
    data.packet_in = p12_1;
    data.key_id_in = 1;
    data.key_id_out = 0;

    RS3_packet_from_cnstrs(cfg, data, &p12_2);

    RS3_key_hash(cfg, k2, p12_1, &o12_1);
    RS3_key_hash(cfg, k1, p12_2, &o12_2);

    printf("\n*** port 1 (~ port 2)\n\n");
    printf("%s\n", RS3_packet_to_string(p12_1));
    printf("%s\n", RS3_key_hash_output_to_string(o12_1));

    printf("\n*** port 2 (~ port 1)\n\n");
    printf("%s\n", RS3_packet_to_string(p12_2));
    printf("%s\n", RS3_key_hash_output_to_string(o12_2));

    if (o12_1 != o12_2) {
      printf("Failed! %u != %u. Exiting.\n", o12_1, o12_2);
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
  RS3_status_t status;

  RS3_pf_t pfs[6] = { RS3_PF_IPV4_SRC, RS3_PF_IPV4_DST, RS3_PF_TCP_SRC,
                      RS3_PF_TCP_DST,  RS3_PF_UDP_SRC,  RS3_PF_UDP_DST, };

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 2);
  RS3_cfg_set_skew_analysis(cfg, true);
  RS3_opts_from_pfs(pfs, 6, &opts, &opts_sz);

  for (size_t i = 0; i < opts_sz; i++)
    RS3_cfg_load_opt(cfg, opts[i]);

  printf("\nConfiguration:\n%s\n", RS3_cfg_to_string(cfg));

  status = RS3_keys_fit_cnstrs(cfg, &mk_p_cnstrs, keys);

  if (status != RS3_STATUS_SUCCESS) {
    printf("Status: %s\n", RS3_status_to_string(status));
    return 1;
  }

  printf("key 1:\n%s\n", RS3_key_to_string(keys[0]));
  printf("key 2:\n%s\n", RS3_key_to_string(keys[1]));

  validate(cfg, keys[0], keys[1]);

  RS3_cfg_delete(cfg);
}
