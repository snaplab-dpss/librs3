#include <rs3.h>

Z3_ast mk_p_cnstrs(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2) {
  RS3_status_t status;

  int subnet_bits = 27;

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

  Z3_ast eq_masked_ips =
      Z3_mk_eq(cfg->ctx, p1_ipv4_src_subnet, p2_ipv4_src_subnet);

  return Z3_simplify(cfg->ctx, eq_masked_ips);
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

  RS3_cfg_delete(cfg);
}
