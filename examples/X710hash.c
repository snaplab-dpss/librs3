#include <rs3.h>

void ipv4_tcp_1() {
  RS3_cfg_t cfg;
  RS3_key_hash_out_t o;
  RS3_packet_t p;
  RS3_key_t k = { 0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41,
                  0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca,
                  0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d,
                  0xa3, 0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b,
                  0xbe, 0xac, 0x01, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 1);
  RS3_packet_init(&p);

  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV4_TCP);

  RS3_ipv4_t ipv4_src = { 66, 9, 149, 187 };
  RS3_ipv4_t ipv4_dst = { 161, 142, 100, 80 };
  RS3_packet_set_ipv4(cfg, ipv4_src, ipv4_dst, &p);

  RS3_port_t tcp_src = {(2794 >> 8) & 0xff, (2794 >> 0) & 0xff };
  RS3_port_t tcp_dst = {(1766 >> 8) & 0xff, (1766 >> 0) & 0xff };
  RS3_packet_set_tcp(cfg, tcp_src, tcp_dst, &p);

  RS3_key_hash(cfg, k, p, &o);

  printf("%s\n", RS3_cfg_to_string(cfg));
  printf("%s\n", RS3_packet_to_string(p));
  printf("%s\n", RS3_key_hash_output_to_string(o));

  RS3_cfg_delete(cfg);
}

void ipv6_tcp_1() {
  RS3_cfg_t cfg;
  RS3_key_hash_out_t o;
  RS3_packet_t p;
  RS3_key_t k = { 0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41,
                  0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca,
                  0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d,
                  0xa3, 0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b,
                  0xbe, 0xac, 0x01, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 1);
  RS3_packet_init(&p);

  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV6_TCP);

  RS3_ipv6_t ipv6_src = { 0x3f, 0xfe, 0x25, 0x01, 0x02, 0x00, 0x1f, 0xff,
                          0,    0,    0,    0,    0,    0,    0,    7 };
  RS3_ipv6_t ipv6_dst = { 0x3f, 0xfe, 0x25, 0x01, 0x02, 0x00, 0x00, 0x03,
                          0,    0,    0,    0,    0,    0,    0,    1 };
  RS3_packet_set_ipv6(cfg, ipv6_src, ipv6_dst, &p);

  RS3_port_t tcp_src = {(2794 >> 8) & 0xff, (2794 >> 0) & 0xff };
  RS3_port_t tcp_dst = {(1766 >> 8) & 0xff, (1766 >> 0) & 0xff };
  RS3_packet_set_tcp(cfg, tcp_src, tcp_dst, &p);

  RS3_key_hash(cfg, k, p, &o);

  printf("%s\n", RS3_cfg_to_string(cfg));
  printf("%s\n", RS3_packet_to_string(p));
  printf("%s\n", RS3_key_hash_output_to_string(o));

  RS3_cfg_delete(cfg);
}

int main() {
  ipv4_tcp_1();
  printf("\n===============================\n");
  ipv6_tcp_1();
}
