#include <rs3.h>

Z3_ast mk_p_cnstrs(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2) {
  return Z3_mk_eq(cfg->ctx, p1.ast, p2.ast);
  RS3_status_t status;
  Z3_ast p1_src_port, p1_dst_port;
  Z3_ast p2_src_port, p2_dst_port;
  Z3_ast and_args[2];

  if (p1.loaded_opt.opt == RS3_OPT_NON_FRAG_IPV4_TCP &&
      p2.loaded_opt.opt == RS3_OPT_NON_FRAG_IPV4_UDP) {
    status = RS3_packet_extract_pf(cfg, p1, RS3_PF_TCP_SRC, &p1_src_port);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    status = RS3_packet_extract_pf(cfg, p1, RS3_PF_TCP_DST, &p1_dst_port);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    status = RS3_packet_extract_pf(cfg, p2, RS3_PF_UDP_SRC, &p2_src_port);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    status = RS3_packet_extract_pf(cfg, p2, RS3_PF_UDP_DST, &p2_dst_port);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    and_args[0] = Z3_mk_eq(cfg->ctx, p1_src_port, p2_src_port);
    and_args[1] = Z3_mk_eq(cfg->ctx, p1_dst_port, p2_dst_port);

    return Z3_mk_and(cfg->ctx, 2, and_args);
  } else if (p1.loaded_opt.opt == RS3_OPT_NON_FRAG_IPV4_UDP &&
             p2.loaded_opt.opt == RS3_OPT_NON_FRAG_IPV4_TCP) {
    status = RS3_packet_extract_pf(cfg, p1, RS3_PF_UDP_SRC, &p1_src_port);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    status = RS3_packet_extract_pf(cfg, p1, RS3_PF_UDP_DST, &p1_dst_port);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    status = RS3_packet_extract_pf(cfg, p2, RS3_PF_TCP_SRC, &p2_src_port);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    status = RS3_packet_extract_pf(cfg, p2, RS3_PF_TCP_DST, &p2_dst_port);
    if (status != RS3_STATUS_SUCCESS)
      return NULL;

    and_args[0] = Z3_mk_eq(cfg->ctx, p1_src_port, p2_src_port);
    and_args[1] = Z3_mk_eq(cfg->ctx, p1_dst_port, p2_dst_port);

    return Z3_mk_and(cfg->ctx, 2, and_args);
  }

  return NULL;
}

int validate(RS3_cfg_t cfg, RS3_key_t k) {
  RS3_packet_t p1, p2;
  RS3_key_hash_out_t o1, o2;
  RS3_packet_from_cnstrs_data_t data;

  for (int i = 0; i < 25; i++) {
    RS3_packet_rand(cfg, &p1);

    data.constraints = &mk_p_cnstrs;
    data.packet_in = p1;
    data.key_id_in = 0;
    data.key_id_out = 0;

    RS3_packet_from_cnstrs(cfg, data, &p2);

    RS3_key_hash(cfg, k, p1, &o1);
    RS3_key_hash(cfg, k, p2, &o2);

    printf("\n===== iteration %d =====\n", i);

    printf("%s\n", RS3_packet_to_string(p1));
    printf("%s\n", RS3_key_hash_output_to_string(o1));

    printf("%s\n", RS3_packet_to_string(p2));
    printf("%s\n", RS3_key_hash_output_to_string(o2));
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
  RS3_key_t k;
  RS3_status_t status;

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 1);
  RS3_cfg_set_skew_analysis(cfg, false);

  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV4_TCP);
  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV4_UDP);

  status = RS3_keys_fit_cnstrs(cfg, &mk_p_cnstrs, &k);

  printf("%s\n", RS3_cfg_to_string(cfg));
  printf("%s\n", RS3_status_to_string(status));

  if (status == RS3_STATUS_SUCCESS)
    printf("result:\n%s\n", RS3_key_to_string(k));

  validate(cfg, k);

  RS3_cfg_delete(cfg);
}
