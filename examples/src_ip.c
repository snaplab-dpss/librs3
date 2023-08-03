#include <rs3.h>

Z3_ast mk_p_cnstrs(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2) {
  RS3_status_t status;
  Z3_ast p1_ipv4_src;
  Z3_ast p2_ipv4_src;
  Z3_ast eq_src_ip;

  status = RS3_packet_extract_pf(cfg, p1, RS3_PF_IPV4_SRC, &p1_ipv4_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p2, RS3_PF_IPV4_SRC, &p2_ipv4_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  eq_src_ip = Z3_mk_eq(cfg->ctx, p1_ipv4_src, p2_ipv4_src);

  return eq_src_ip;
}

int main() {
  RS3_cfg_t cfg;
  RS3_key_t k;
  RS3_status_t status;

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 1);
  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV4_TCP);

  status = RS3_keys_fit_cnstrs(cfg, &mk_p_cnstrs, &k);

  printf("%s\n", RS3_cfg_to_string(cfg));
  printf("%s\n", RS3_status_to_string(status));

  if (status == RS3_STATUS_SUCCESS)
    printf("result:\n%s\n", RS3_key_to_string(k));

  status = RS3_keys_test_cnstrs(cfg, &mk_p_cnstrs, &k);
  printf("valid keys: %s\n", RS3_status_to_string(status));

  RS3_cfg_delete(cfg);
}
