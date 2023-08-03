#include <rs3.h>
#include <assert.h>

#define NUM_TARGET_SUBNETS 3

#define SUBNET_BITS_0 27
#define SUBNET_BITS_1 30
#define SUBNET_BITS_2 32

int subnets_bits[NUM_TARGET_SUBNETS] = { SUBNET_BITS_0, SUBNET_BITS_1,
                                         SUBNET_BITS_2 };

Z3_ast mk_subnet_cnstr(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2,
                       int subnet_idx) {
  RS3_status_t status;

  assert(subnet_idx < NUM_TARGET_SUBNETS);
  int subnet_bits = subnets_bits[subnet_idx];

  Z3_ast p1_ipv4_src;
  Z3_ast p2_ipv4_src;

  status = RS3_packet_extract_pf(cfg, p1, RS3_PF_IPV4_SRC, &p1_ipv4_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p2, RS3_PF_IPV4_SRC, &p2_ipv4_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  Z3_ast p1_ipv4_src_subnet =
      Z3_mk_extract(cfg->ctx, 31, 31 - (subnet_bits - 1), p1_ipv4_src);

  Z3_ast p2_ipv4_src_subnet =
      Z3_mk_extract(cfg->ctx, 31, 31 - (subnet_bits - 1), p2_ipv4_src);

  return Z3_mk_eq(cfg->ctx, p1_ipv4_src_subnet, p2_ipv4_src_subnet);
}

Z3_ast mk_p_cnstrs(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2) {
  Z3_ast eq_subnets_exprs[NUM_TARGET_SUBNETS];

  for (int i = 0; i < NUM_TARGET_SUBNETS; i++) {
    eq_subnets_exprs[i] = mk_subnet_cnstr(cfg, p1, p2, i);
  }

  Z3_ast final_expr = Z3_mk_or(cfg->ctx, NUM_TARGET_SUBNETS, eq_subnets_exprs);

  return Z3_simplify(cfg->ctx, final_expr);
}

Z3_ast mk_subnet0_cnstr(RS3_cfg_t cfg, RS3_packet_ast_t p1,
                        RS3_packet_ast_t p2) {
  return mk_subnet_cnstr(cfg, p1, p2, 0);
}

Z3_ast mk_subnet1_cnstr(RS3_cfg_t cfg, RS3_packet_ast_t p1,
                        RS3_packet_ast_t p2) {
  return mk_subnet_cnstr(cfg, p1, p2, 1);
}

Z3_ast mk_subnet2_cnstr(RS3_cfg_t cfg, RS3_packet_ast_t p1,
                        RS3_packet_ast_t p2) {
  return mk_subnet_cnstr(cfg, p1, p2, 2);
}

int validate(RS3_cfg_t cfg, RS3_key_t k) {
  RS3_packet_t p1;
  RS3_key_hash_out_t o1;
  RS3_packet_from_cnstrs_data_t data;

  RS3_packet_rand(cfg, &p1);

  RS3_cnstrs_func cnstrs_funcs[NUM_TARGET_SUBNETS] = { &mk_subnet0_cnstr,
                                                       &mk_subnet1_cnstr,
                                                       &mk_subnet2_cnstr };

  for (int i = 0; i < NUM_TARGET_SUBNETS; i++) {
    RS3_packet_t p2;
    RS3_key_hash_out_t o2;

    data.constraints = cnstrs_funcs[i];
    data.packet_in = p1;
    data.key_id_in = 0;
    data.key_id_out = 0;

    RS3_packet_from_cnstrs(cfg, data, &p2);

    RS3_key_hash(cfg, k, p1, &o1);
    RS3_key_hash(cfg, k, p2, &o2);

    printf("\n===== Subnet %d (%d bits)=====\n", i, subnets_bits[i]);

    printf("%s\n", RS3_packet_to_string(p1));
    printf("%s\n", RS3_key_hash_output_to_string(o1));

    printf("%s\n", RS3_packet_to_string(p2));
    printf("%s\n", RS3_key_hash_output_to_string(o2));

    if (o1 != o2) {
      printf("Failed! %u != %u. Exiting.\n", o1, o2);
      return 0;
    }
  }

  return 1;
}

int main() {
  RS3_cfg_t cfg;
  RS3_key_t key;
  RS3_opt_t *opts;
  size_t opts_sz;
  RS3_status_t status;

  RS3_pf_t pfs[6] = {
    RS3_PF_IPV4_SRC, RS3_PF_IPV4_DST, RS3_PF_TCP_SRC,
    RS3_PF_TCP_DST,  RS3_PF_UDP_SRC,  RS3_PF_UDP_DST,
  };

  RS3_skew_analysis_params_t skew_params = { .pcap_fname = NULL,
                                             .time_limit = -1 };

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 1);
  RS3_cfg_set_skew_analysis(cfg, true);
  RS3_cfg_set_number_of_processes(cfg, 8);
  RS3_cfg_set_skew_analysis_parameters(cfg, skew_params);
  RS3_opts_from_pfs(pfs, 6, &opts, &opts_sz);

  for (size_t i = 0; i < opts_sz; i++)
    RS3_cfg_load_opt(cfg, opts[i]);

  printf("\nConfiguration:\n%s\n", RS3_cfg_to_string(cfg));

  status = RS3_keys_fit_cnstrs(cfg, &mk_p_cnstrs, &key);

  if (status != RS3_STATUS_SUCCESS) {
    printf("Status: %s\n", RS3_status_to_string(status));
    return 1;
  }

  printf("key:\n%s\n", RS3_key_to_string(key));
  validate(cfg, key);

  RS3_cfg_delete(cfg);
}
