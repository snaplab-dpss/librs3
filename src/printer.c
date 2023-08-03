#include "../include/rs3.h"
#include "printer.h"
#include "packet.h"
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#define _4_RS3_BYTE_T_TO_UINT32_T(v)                                           \
  ((uint32_t)(                                                                 \
      ((BYTE_FROM_BYTES((v), 0)) << 24) + ((BYTE_FROM_BYTES((v), 1)) << 16) +  \
      ((BYTE_FROM_BYTES((v), 2)) << 8) + ((BYTE_FROM_BYTES((v), 3)) << 0)))

#define _3_RS3_BYTE_T_TO_UINT32_T(v)                                           \
  ((uint32_t)(((BYTE_FROM_BYTES((v), 0)) << 16) +                              \
              ((BYTE_FROM_BYTES((v), 1)) << 8) +                               \
              ((BYTE_FROM_BYTES((v), 2)) << 0)))

#define _2_RS3_BYTE_T_TO_UINT32_T(v)                                           \
  ((uint16_t)(((BYTE_FROM_BYTES((v), 0)) << 8) +                               \
              ((BYTE_FROM_BYTES((v), 1)) << 0)))

#define APPEND(dst, f_, ...)                                                   \
  {                                                                            \
    char buffer[RS3_STRING_SZ];                                                \
    snprintf(buffer, RS3_STRING_SZ - 1, (f_), ##__VA_ARGS__);                  \
    size_t current_size = strlen(dst);                                         \
    size_t to_append_size = strlen(buffer);                                    \
    assert(current_size + to_append_size < RS3_STRING_SZ);                     \
    strcat((dst), (buffer));                                                   \
  }

RS3_string_t RS3_packet_to_string(RS3_packet_t p) {
  static char result[RS3_STRING_SZ];

  result[0] = '\0';

  if (RS3_packet_has_pf(p, RS3_PF_VXLAN_UDP_OUTER)) {
    APPEND(result, "udp outer : %u\n",
           _2_RS3_BYTE_T_TO_UINT32_T(p.vxlan.outer));
  }

  if (RS3_packet_has_pf(p, RS3_PF_VXLAN_VNI))
    APPEND(result, "vni       : %u\n", _3_RS3_BYTE_T_TO_UINT32_T(p.vxlan.vni));

  if (RS3_packet_has_pf(p, RS3_PF_IPV4_SRC))
    APPEND(result, "ipv4 src  : %u.%u.%u.%u\n", BYTE_FROM_BYTES(p.ipv4.src, 0),
           BYTE_FROM_BYTES(p.ipv4.src, 1), BYTE_FROM_BYTES(p.ipv4.src, 2),
           BYTE_FROM_BYTES(p.ipv4.src, 3));

  if (RS3_packet_has_pf(p, RS3_PF_IPV4_DST))
    APPEND(result, "ipv4 dst  : %u.%u.%u.%u\n", BYTE_FROM_BYTES(p.ipv4.dst, 0),
           BYTE_FROM_BYTES(p.ipv4.dst, 1), BYTE_FROM_BYTES(p.ipv4.dst, 2),
           BYTE_FROM_BYTES(p.ipv4.dst, 3));

  if (RS3_packet_has_pf(p, RS3_PF_IPV6_SRC))
    APPEND(result, "ipv6 src  : "
                   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%"
                   "02x:%02x%02x\n",
           BYTE_FROM_BYTES(p.ipv6.src, 0), BYTE_FROM_BYTES(p.ipv6.src, 1),
           BYTE_FROM_BYTES(p.ipv6.src, 2), BYTE_FROM_BYTES(p.ipv6.src, 3),
           BYTE_FROM_BYTES(p.ipv6.src, 4), BYTE_FROM_BYTES(p.ipv6.src, 5),
           BYTE_FROM_BYTES(p.ipv6.src, 6), BYTE_FROM_BYTES(p.ipv6.src, 7),
           BYTE_FROM_BYTES(p.ipv6.src, 8), BYTE_FROM_BYTES(p.ipv6.src, 9),
           BYTE_FROM_BYTES(p.ipv6.src, 10), BYTE_FROM_BYTES(p.ipv6.src, 11),
           BYTE_FROM_BYTES(p.ipv6.src, 12), BYTE_FROM_BYTES(p.ipv6.src, 13),
           BYTE_FROM_BYTES(p.ipv6.src, 14), BYTE_FROM_BYTES(p.ipv6.src, 15));

  if (RS3_packet_has_pf(p, RS3_PF_IPV6_DST))
    APPEND(result, "ipv6 dst  : "
                   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%"
                   "02x:%02x%02x\n",
           BYTE_FROM_BYTES(p.ipv6.dst, 0), BYTE_FROM_BYTES(p.ipv6.dst, 1),
           BYTE_FROM_BYTES(p.ipv6.dst, 2), BYTE_FROM_BYTES(p.ipv6.dst, 3),
           BYTE_FROM_BYTES(p.ipv6.dst, 4), BYTE_FROM_BYTES(p.ipv6.dst, 5),
           BYTE_FROM_BYTES(p.ipv6.dst, 6), BYTE_FROM_BYTES(p.ipv6.dst, 7),
           BYTE_FROM_BYTES(p.ipv6.dst, 8), BYTE_FROM_BYTES(p.ipv6.dst, 9),
           BYTE_FROM_BYTES(p.ipv6.dst, 10), BYTE_FROM_BYTES(p.ipv6.dst, 11),
           BYTE_FROM_BYTES(p.ipv6.dst, 12), BYTE_FROM_BYTES(p.ipv6.dst, 13),
           BYTE_FROM_BYTES(p.ipv6.dst, 14), BYTE_FROM_BYTES(p.ipv6.dst, 15));

  if (RS3_packet_has_pf(p, RS3_PF_TCP_SRC))
    APPEND(result, "tcp src   : %u\n", _2_RS3_BYTE_T_TO_UINT32_T(p.tcp.src));

  if (RS3_packet_has_pf(p, RS3_PF_TCP_DST))
    APPEND(result, "tcp dst   : %u\n", _2_RS3_BYTE_T_TO_UINT32_T(p.tcp.dst));

  if (RS3_packet_has_pf(p, RS3_PF_UDP_SRC))
    APPEND(result, "udp src   : %u\n", _2_RS3_BYTE_T_TO_UINT32_T(p.udp.src));

  if (RS3_packet_has_pf(p, RS3_PF_UDP_DST))
    APPEND(result, "udp dst   : %u\n", _2_RS3_BYTE_T_TO_UINT32_T(p.udp.dst));

  if (RS3_packet_has_pf(p, RS3_PF_SCTP_SRC))
    APPEND(result, "sctp src  : %u\n", _2_RS3_BYTE_T_TO_UINT32_T(p.sctp.src));

  if (RS3_packet_has_pf(p, RS3_PF_SCTP_DST))
    APPEND(result, "sctp dst  : %u\n", _2_RS3_BYTE_T_TO_UINT32_T(p.sctp.dst));

  if (RS3_packet_has_pf(p, RS3_PF_SCTP_V_TAG))
    APPEND(result, "sctp v tag: %u\n", _4_RS3_BYTE_T_TO_UINT32_T(p.sctp.tag));

  return result;
}

RS3_string_t RS3_key_to_string(RS3_key_t k) {
  static char result[RS3_STRING_SZ];
  char *ptr;

  ptr = result;
  for (int i = 0; i < KEY_SIZE; i++) {
    sprintf(ptr, "%02x ", k[i] & 0xff);
    ptr += 3;

    if ((i + 1) % 8 == 0)
      *(ptr++) = '\n';
  }

  *(ptr++) = '\n';
  *ptr = '\0';

  return result;
}

RS3_string_t RS3_key_hash_output_to_string(RS3_key_hash_out_t output) {
  static char result[RS3_STRING_SZ];

  result[0] = '\0';

  sprintf(result, "%02x %02x %02x %02x", (output >> 24) & 0xff,
          (output >> 16) & 0xff, (output >> 8) & 0xff, (output >> 0) & 0xff);

  return result;
}

RS3_string_t RS3_status_to_string(RS3_status_t status) {
  static char result[RS3_STRING_SZ];

  result[0] = '\0';

  switch (status) {
    case RS3_STATUS_SUCCESS:
      sprintf(result, "success");
      break;
    case RS3_STATUS_NO_SOLUTION:
      sprintf(result, "no solution");
      break;
    case RS3_STATUS_BAD_SOLUTION:
      sprintf(result, "bad solution");
      break;
    case RS3_STATUS_HAS_SOLUTION:
      sprintf(result, "has solution");
      break;
    case RS3_STATUS_TIMEOUT:
      sprintf(result, "timeout");
      break;
    case RS3_STATUS_PF_UNKNOWN:
      sprintf(result, "unknown packet field");
      break;
    case RS3_STATUS_PF_LOADED:
      sprintf(result, "packet field loaded");
      break;
    case RS3_STATUS_PF_NOT_LOADED:
      sprintf(result, "packet field not loaded");
      break;
    case RS3_STATUS_PF_INCOMPATIBLE:
      sprintf(result, "incompatible packet field");
      break;
    case RS3_STATUS_OPT_UNKNOWN:
      sprintf(result, "unknown option");
      break;
    case RS3_STATUS_OPT_LOADED:
      sprintf(result, "option loaded");
      break;
    case RS3_STATUS_OPT_NOT_LOADED:
      sprintf(result, "option not loaded");
      break;
    case RS3_STATUS_INVALID_IOPT:
      sprintf(result, "option index invalid (must be < cfg->n_loaded_opts)");
      break;
    case RS3_STATUS_IO_ERROR:
      sprintf(result, "input/output error (maybe file not found)");
      break;
    case RS3_STATUS_FAILURE:
      sprintf(result, "failure");
      break;
    case RS3_STATUS_NOP:
      sprintf(result, "no operation made");
      break;
  }

  return result;
}

RS3_string_t RS3_opt_to_string(RS3_opt_t opt) {
  static char result[RS3_STRING_SZ];

  result[0] = '\0';

  switch (opt) {
    case RS3_OPT_GENEVE_OAM:
      sprintf(result, "Geneve OAM");
      break;
    case RS3_OPT_VXLAN_GPE_OAM:
      sprintf(result, "VXLAN GPE OAM");
      break;
    case RS3_OPT_NON_FRAG_IPV4_TCP:
      sprintf(result, "Non-frag TCP/IPv4");
      break;
    case RS3_OPT_NON_FRAG_IPV4_UDP:
      sprintf(result, "Non-frag UDP/IPv4");
      break;
    case RS3_OPT_NON_FRAG_IPV4_SCTP:
      sprintf(result, "Non-frag SCTP/IPv4");
      break;
      sprintf(result, "Frag IPv4");
      break;
    case RS3_OPT_NON_FRAG_IPV6_TCP:
      sprintf(result, "Non-frag TCP/IPv6");
      break;
    case RS3_OPT_NON_FRAG_IPV6_UDP:
      sprintf(result, "Non-frag UDP/IPv6");
      break;
    case RS3_OPT_NON_FRAG_IPV6_SCTP:
      sprintf(result, "Non-frag SCTP/IPv6");
      break;
    case RS3_OPT_NON_FRAG_IPV6:
      sprintf(result, "Non-frag IPv6");
      break;
    case RS3_OPT_FRAG_IPV6:
      sprintf(result, "Frag IPv6");
      break;
    case RS3_OPT_ETHERTYPE:
      sprintf(result, "Ethertype");
      break;
  }

  return result;
}

RS3_string_t RS3_pf_to_string(RS3_pf_t pf) {
  static char result[RS3_STRING_SZ];

  result[0] = '\0';

  switch (pf) {
    case RS3_PF_VXLAN_UDP_OUTER:
      sprintf(result, "VXLAN UDP outer");
      break;
    case RS3_PF_VXLAN_VNI:
      sprintf(result, "VXLAN VNI");
      break;
    case RS3_PF_IPV6_SRC:
      sprintf(result, "IPv6 src");
      break;
    case RS3_PF_IPV6_DST:
      sprintf(result, "IPv6 dst");
      break;
    case RS3_PF_IPV4_SRC:
      sprintf(result, "IPv4 src");
      break;
    case RS3_PF_IPV4_DST:
      sprintf(result, "IPv4 dst");
      break;
    case RS3_PF_TCP_SRC:
      sprintf(result, "TCP src");
      break;
    case RS3_PF_TCP_DST:
      sprintf(result, "TCP dst");
      break;
    case RS3_PF_UDP_SRC:
      sprintf(result, "UDP src");
      break;
    case RS3_PF_UDP_DST:
      sprintf(result, "UDP dst");
      break;
    case RS3_PF_SCTP_SRC:
      sprintf(result, "SCTP src");
      break;
    case RS3_PF_SCTP_DST:
      sprintf(result, "SCTP dst");
      break;
    case RS3_PF_SCTP_V_TAG:
      sprintf(result, "SCTP verification");
      break;
    case RS3_PF_ETHERTYPE:
      sprintf(result, "Ethertype");
      break;
  }

  return result;
}

RS3_string_t RS3_cfg_to_string(RS3_cfg_t cfg) {
  static char result[RS3_STRING_SZ];

  result[0] = '\0';

  APPEND(result, "cores: %d\n", cfg->n_procs);
  APPEND(result, "keys : %d\n", cfg->n_keys);
  APPEND(result, "cfgs :\n");

  for (unsigned iopt = 0; iopt < cfg->n_loaded_opts; iopt++) {
    APPEND(result, "\topt: %s\n",
           RS3_opt_to_string(cfg->loaded_opts[iopt].opt));
    APPEND(result, "\tsz : %u bits\n", cfg->loaded_opts[iopt].sz);
    APPEND(result, "\tpfs:\n");

    for (int ipf = RS3_FIRST_PF; ipf <= RS3_LAST_PF; ipf++)
      if (RS3_loaded_opt_check_pf(cfg->loaded_opts[iopt], (RS3_pf_t)ipf) ==
          RS3_STATUS_PF_LOADED)
        APPEND(result, "\t\t* %s\n", RS3_pf_to_string((RS3_pf_t)ipf));
  }

  return result;
}

RS3_string_t RS3_stats_to_string(RS3_stats_t stats) {
  static char result[RS3_STRING_SZ];
  float percentage;
  unsigned n_packets;

  result[0] = '\0';

  APPEND(result, "Used LUT entries: %u\n", stats.used_lut_entries);

  return result;
}
