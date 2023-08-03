#include "../include/rs3.h"

Z3_ast RS3_cnstr_symmetric_ip(RS3_cfg_t cfg, RS3_packet_ast_t p1,
                              RS3_packet_ast_t p2) {
  RS3_status_t status;
  Z3_ast p1_ipv4_src, p1_ipv4_dst;
  Z3_ast p2_ipv4_src, p2_ipv4_dst;
  Z3_ast and_args[2];

  status = RS3_packet_extract_pf(cfg, p1, RS3_PF_IPV4_SRC, &p1_ipv4_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p1, RS3_PF_IPV4_DST, &p1_ipv4_dst);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p2, RS3_PF_IPV4_SRC, &p2_ipv4_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p2, RS3_PF_IPV4_DST, &p2_ipv4_dst);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  and_args[0] = Z3_mk_eq(cfg->ctx, p1_ipv4_src, p2_ipv4_dst);
  and_args[1] = Z3_mk_eq(cfg->ctx, p1_ipv4_dst, p2_ipv4_src);

  return Z3_mk_and(cfg->ctx, 2, and_args);
}

/**
 * @example
 */
Z3_ast RS3_cnstr_symmetric_tcp(RS3_cfg_t cfg, RS3_packet_ast_t p1,
                               RS3_packet_ast_t p2) {
  RS3_status_t status;
  Z3_ast p1_tcp_src, p1_tcp_dst;
  Z3_ast p2_tcp_src, p2_tcp_dst;
  Z3_ast and_args[2];

  status = RS3_packet_extract_pf(cfg, p1, RS3_PF_TCP_SRC, &p1_tcp_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p1, RS3_PF_TCP_DST, &p1_tcp_dst);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p2, RS3_PF_TCP_SRC, &p2_tcp_src);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  status = RS3_packet_extract_pf(cfg, p2, RS3_PF_TCP_DST, &p2_tcp_dst);
  if (status != RS3_STATUS_SUCCESS)
    return NULL;

  and_args[0] = Z3_mk_eq(cfg->ctx, p1_tcp_src, p2_tcp_dst);
  and_args[1] = Z3_mk_eq(cfg->ctx, p1_tcp_dst, p2_tcp_src);

  return Z3_mk_and(cfg->ctx, 2, and_args);
}

/**
 * @example
 */
Z3_ast RS3_cnstr_symmetric_tcp_ip(RS3_cfg_t cfg, RS3_packet_ast_t p1,
                                  RS3_packet_ast_t p2) {
  Z3_ast symmetric_ip;
  Z3_ast symmetric_tcp;
  Z3_ast and_args[2];

  symmetric_ip = RS3_cnstr_symmetric_ip(cfg, p1, p2);
  if (symmetric_ip == NULL)
    return NULL;

  symmetric_tcp = RS3_cnstr_symmetric_tcp(cfg, p1, p2);
  if (symmetric_tcp == NULL)
    return NULL;

  and_args[0] = symmetric_ip;
  and_args[1] = symmetric_tcp;

  return Z3_mk_and(cfg->ctx, 2, and_args);
}
