#include <rs3.h>

Z3_ast RS3_cnstr_symmetric_ipv6(RS3_cfg_t cfg, RS3_packet_ast_t p1,
                                RS3_packet_ast_t p2) {
  RS3_status_t status;
  Z3_ast p1_ipv6_src, p1_ipv6_dst;
  Z3_ast p2_ipv6_src, p2_ipv6_dst;
  Z3_ast and_args[2];

  status = RS3_packet_extract_pf(cfg, p1, RS3_PF_IPV6_SRC, &p1_ipv6_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p1, RS3_PF_IPV6_DST, &p1_ipv6_dst);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p2, RS3_PF_IPV6_SRC, &p2_ipv6_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p2, RS3_PF_IPV6_DST, &p2_ipv6_dst);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  and_args[0] = Z3_mk_eq(cfg->ctx, p1_ipv6_src, p2_ipv6_dst);
  and_args[1] = Z3_mk_eq(cfg->ctx, p1_ipv6_dst, p2_ipv6_src);

  return Z3_mk_and(cfg->ctx, 2, and_args);
}

Z3_ast mk_p_cnstrs(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2) {
  Z3_ast symmetric_ip;
  Z3_ast symmetric_tcp;
  Z3_ast and_args[2];

  symmetric_ip = RS3_cnstr_symmetric_ipv6(cfg, p1, p2);
  if (symmetric_ip == NULL)
    return NULL;

  symmetric_tcp = RS3_cnstr_symmetric_tcp(cfg, p1, p2);
  if (symmetric_tcp == NULL)
    return NULL;

  and_args[0] = symmetric_ip;
  and_args[1] = symmetric_tcp;

  return Z3_mk_and(cfg->ctx, 2, and_args);
}

int main() {
  RS3_status_t status;
  RS3_cfg_t cfg;
  RS3_key_t k;

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 1);

  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV6_TCP);

  status = RS3_keys_fit_cnstrs(cfg, &mk_p_cnstrs, &k);

  printf("%s\n", RS3_cfg_to_string(cfg));
  printf("%s\n", RS3_status_to_string(status));

  if (status == RS3_STATUS_SUCCESS) {
    printf("result:\n%s\n", RS3_key_to_string(k));
  }

  RS3_cfg_delete(cfg);
}
