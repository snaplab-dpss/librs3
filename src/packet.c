#include "../include/rs3.h"
#include "packet.h"
#include "util.h"
#include "config.h"

#include <stdlib.h>
#include <assert.h>

size_t RS3_pf_sz_bits(RS3_pf_t pf) {
  switch (pf) {
    case RS3_PF_VXLAN_UDP_OUTER:
      return sizeof(RS3_port_t) * 8;
    case RS3_PF_VXLAN_VNI:
      return sizeof(RS3_vni_t) * 8;
    case RS3_PF_IPV4_SRC:
      return sizeof(RS3_ipv4_t) * 8;
    case RS3_PF_IPV4_DST:
      return sizeof(RS3_ipv4_t) * 8;
    case RS3_PF_IPV6_SRC:
      return sizeof(RS3_ipv6_t) * 8;
    case RS3_PF_IPV6_DST:
      return sizeof(RS3_ipv6_t) * 8;
    case RS3_PF_TCP_SRC:
      return sizeof(RS3_port_t) * 8;
    case RS3_PF_TCP_DST:
      return sizeof(RS3_port_t) * 8;
    case RS3_PF_UDP_SRC:
      return sizeof(RS3_port_t) * 8;
    case RS3_PF_UDP_DST:
      return sizeof(RS3_port_t) * 8;
    case RS3_PF_SCTP_SRC:
      return sizeof(RS3_port_t) * 8;
    case RS3_PF_SCTP_DST:
      return sizeof(RS3_port_t) * 8;
    case RS3_PF_SCTP_V_TAG:
      return sizeof(RS3_v_tag_t) * 8;
    case RS3_PF_ETHERTYPE:
      return 6;
    default:
      assert(false);
  }
}

RS3_bytes_t RS3_packet_get_field(RS3_packet_t *p, RS3_pf_t pf) {
  switch (pf) {
    case RS3_PF_VXLAN_UDP_OUTER:
      return (RS3_bytes_t)p->vxlan.outer;
    case RS3_PF_VXLAN_VNI:
      return (RS3_bytes_t)p->vxlan.vni;
    case RS3_PF_IPV4_SRC:
      return (RS3_bytes_t)p->ipv4.src;
    case RS3_PF_IPV4_DST:
      return (RS3_bytes_t)p->ipv4.dst;
    case RS3_PF_IPV6_SRC:
      return (RS3_bytes_t)p->ipv6.src;
    case RS3_PF_IPV6_DST:
      return (RS3_bytes_t)p->ipv6.dst;
    case RS3_PF_TCP_SRC:
      return (RS3_bytes_t)p->tcp.src;
    case RS3_PF_TCP_DST:
      return (RS3_bytes_t)p->tcp.dst;
    case RS3_PF_UDP_SRC:
      return (RS3_bytes_t)p->udp.src;
    case RS3_PF_UDP_DST:
      return (RS3_bytes_t)p->udp.dst;
    case RS3_PF_SCTP_SRC:
      return (RS3_bytes_t)p->sctp.src;
    case RS3_PF_SCTP_DST:
      return (RS3_bytes_t)p->sctp.dst;
    case RS3_PF_SCTP_V_TAG:
      return (RS3_bytes_t)p->sctp.tag;
    case RS3_PF_ETHERTYPE:
      return (RS3_bytes_t)p->ethertype;
  }

  fprintf(stderr, "ERROR: field %d not found on header\n", pf);
  assert(false);
}

void RS3_packet_init(RS3_packet_t *p) { p->cfg = 0; }

bool RS3_packet_has_pf(RS3_packet_t p, RS3_pf_t pf) {
  return (p.cfg >> pf) & 1;
}

RS3_status_t RS3_packet_set_pf(RS3_cfg_t cfg, RS3_pf_t pf, RS3_bytes_t v,
                               RS3_packet_t *p) {
  RS3_bytes_t field;
  RS3_in_cfg_t test_cfg;
  unsigned n_pfs;
  bool compatible_pf;

  test_cfg = p->cfg | (1 << pf);

  if (!RS3_cfg_are_compatible_pfs(cfg, test_cfg))
    return RS3_STATUS_PF_INCOMPATIBLE;

  p->cfg = test_cfg;
  field = RS3_packet_get_field(p, pf);

  for (unsigned byte = 0; byte < RS3_pf_sz(pf); byte++)
    field[byte] = v[byte];

  return RS3_STATUS_SUCCESS;
}

RS3_status_t RS3_packet_set_ethertype(RS3_cfg_t cfg, RS3_ethertype_t ethertype,
                                      RS3_packet_t *p) {
  return RS3_packet_set_pf(cfg, RS3_PF_ETHERTYPE, ethertype, p);
}

RS3_status_t RS3_packet_set_ipv4(RS3_cfg_t cfg, RS3_ipv4_t src, RS3_ipv4_t dst,
                                 RS3_packet_t *p) {
  RS3_status_t status;

  status = RS3_packet_set_pf(cfg, RS3_PF_IPV4_SRC, src, p);
  if (status != RS3_STATUS_SUCCESS)
    return status;

  status = RS3_packet_set_pf(cfg, RS3_PF_IPV4_DST, dst, p);
  return status;
}

RS3_status_t RS3_packet_set_ipv6(RS3_cfg_t cfg, RS3_ipv6_t src, RS3_ipv6_t dst,
                                 RS3_packet_t *p) {
  RS3_status_t status;

  status = RS3_packet_set_pf(cfg, RS3_PF_IPV6_SRC, src, p);
  if (status != RS3_STATUS_SUCCESS)
    return status;

  status = RS3_packet_set_pf(cfg, RS3_PF_IPV6_DST, dst, p);
  return status;
}

RS3_status_t RS3_packet_set_tcp(RS3_cfg_t cfg, RS3_port_t src, RS3_port_t dst,
                                RS3_packet_t *p) {
  RS3_status_t status;

  status = RS3_packet_set_pf(cfg, RS3_PF_TCP_SRC, src, p);
  if (status != RS3_STATUS_SUCCESS)
    return status;

  status = RS3_packet_set_pf(cfg, RS3_PF_TCP_DST, dst, p);
  return status;
}

RS3_status_t RS3_packet_set_udp(RS3_cfg_t cfg, RS3_port_t src, RS3_port_t dst,
                                RS3_packet_t *p) {
  RS3_status_t status;

  status = RS3_packet_set_pf(cfg, RS3_PF_UDP_SRC, src, p);
  if (status != RS3_STATUS_SUCCESS)
    return status;

  status = RS3_packet_set_pf(cfg, RS3_PF_UDP_DST, dst, p);
  return status;
}

RS3_status_t RS3_packet_set_sctp(RS3_cfg_t cfg, RS3_port_t src, RS3_port_t dst,
                                 RS3_v_tag_t tag, RS3_packet_t *p) {
  RS3_status_t status;

  status = RS3_packet_set_pf(cfg, RS3_PF_SCTP_SRC, src, p);
  if (status != RS3_STATUS_SUCCESS)
    return status;

  status = RS3_packet_set_pf(cfg, RS3_PF_SCTP_DST, dst, p);
  if (status != RS3_STATUS_SUCCESS)
    return status;

  status = RS3_packet_set_pf(cfg, RS3_PF_SCTP_V_TAG, tag, p);
  return status;
}

RS3_status_t RS3_packet_set_vxlan(RS3_cfg_t cfg, RS3_port_t outer,
                                  RS3_vni_t vni, out RS3_packet_t *p) {
  RS3_status_t status;

  status = RS3_packet_set_pf(cfg, RS3_PF_VXLAN_UDP_OUTER, outer, p);
  if (status != RS3_STATUS_SUCCESS)
    return status;

  status = RS3_packet_set_pf(cfg, RS3_PF_VXLAN_VNI, vni, p);
  return status;
}

RS3_status_t RS3_packet_rand(RS3_cfg_t cfg, out RS3_packet_t *p) {
  RS3_pf_t pf;
  unsigned chosen_opt;
  RS3_bytes_t v;
  unsigned sz;

  RS3_packet_init(p);
  init_rand();

  v = NULL;
  chosen_opt = rand() % cfg->n_loaded_opts;

  for (int ipf = RS3_FIRST_PF; ipf <= RS3_LAST_PF; ipf++) {
    pf = (RS3_pf_t)ipf;

    if (RS3_loaded_opt_check_pf(cfg->loaded_opts[chosen_opt], pf) !=
        RS3_STATUS_PF_LOADED)
      continue;

    sz = RS3_pf_sz(pf);
    v = (RS3_bytes_t)realloc(v, sizeof(RS3_byte_t) * sz);

    for (unsigned byte = 0; byte < sz; byte++)
      v[byte] = (RS3_byte_t)rand() & 0xff;

    RS3_packet_set_pf(cfg, pf, v, p);
  }

  free(v);

  return RS3_STATUS_SUCCESS;
}

RS3_status_t RS3_packets_rand(RS3_cfg_t cfg, unsigned n_packets,
                              out RS3_packet_t **p) {
  *p = (RS3_packet_t *)malloc(sizeof(RS3_packet_t) * n_packets);

  for (unsigned ipacket = 0; ipacket < n_packets; ipacket++)
    RS3_packet_rand(cfg, &((*p)[ipacket]));

  return RS3_STATUS_SUCCESS;
}

RS3_status_t RS3_packet_to_loaded_opt(RS3_cfg_t cfg, RS3_packet_t p,
                                      RS3_loaded_opt_t *loaded_opt) {
  unsigned n_opts;
  int chosen_iopt;

  int match;
  int max_match;

  max_match = 0;
  chosen_iopt = -1;
  n_opts = cfg->n_loaded_opts;

  for (unsigned iopt = 0; iopt < n_opts; iopt++) {
    match = 0;

    for (unsigned ipf = RS3_FIRST_PF; ipf <= RS3_LAST_PF; ipf++) {
      if (RS3_loaded_opt_check_pf(cfg->loaded_opts[iopt], (RS3_pf_t)ipf) ==
          RS3_STATUS_PF_NOT_LOADED)
        continue;

      if (!RS3_packet_has_pf(p, (RS3_pf_t)ipf)) {
        match = 0;
        break;
      }

      match++;
    }

    if (match > max_match) {
      chosen_iopt = iopt;
      max_match = match;
    }
  }

  if (chosen_iopt == -1)
    return RS3_STATUS_NO_SOLUTION;

  *loaded_opt = cfg->loaded_opts[chosen_iopt];

  return RS3_STATUS_SUCCESS;
}
