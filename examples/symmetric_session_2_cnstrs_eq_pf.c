#include <rs3.h>
#include <stdlib.h>

Z3_ast mk_p_cnstrs(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2) {
  // TCP/IP for the first key
  if (p1.key_id == 0 && p2.key_id == 0)
    return Z3_mk_eq(cfg->ctx, p1.ast, p2.ast);

  // symmetric TCP/IP between the first and the second keys (devices)
  if (p1.key_id == 0 && p2.key_id == 1)
    return RS3_cnstr_symmetric_tcp_ip(cfg, p1, p2);

  return NULL;
}

void validate(RS3_cfg_t cfg, RS3_key_t k1, RS3_key_t k2) {
  RS3_packet_t p1_1, p1_2, p12_1, p12_2;
  RS3_key_hash_out_t o1_1, o1_2, o12_1, o12_2;
  RS3_packet_from_cnstrs_data_t data;

  for (int i = 0; i < 25; i++) {
    RS3_packet_rand(cfg, &p1_1);
    RS3_packet_rand(cfg, &p12_1);

    data.constraints = &mk_p_cnstrs;
    data.packet_in = p1_1;
    data.key_id_in = 0;
    data.key_id_out = 0;

    RS3_packet_from_cnstrs(cfg, data, &p1_2);

    data.constraints = &mk_p_cnstrs;
    data.packet_in = p12_1;
    data.key_id_in = 0;
    data.key_id_out = 1;

    RS3_packet_from_cnstrs(cfg, data, &p12_2);

    RS3_key_hash(cfg, k1, p1_1, &o1_1);
    RS3_key_hash(cfg, k1, p1_2, &o1_2);
    RS3_key_hash(cfg, k2, p12_1, &o12_1);
    RS3_key_hash(cfg, k1, p12_2, &o12_2);

    printf("\n===== iteration %d =====\n", i);

    printf("\n*** port 1 \n\n");
    printf("%s\n", RS3_packet_to_string(p1_1));
    printf("%s\n", RS3_key_hash_output_to_string(o1_1));

    printf("%s\n", RS3_packet_to_string(p1_2));
    printf("%s\n", RS3_key_hash_output_to_string(o1_2));
    ;

    if (o1_1 != o1_2) {
      printf("Failed! %u != %u. Exiting.\n", o1_1, o1_2);
      exit(1);
    }

    printf("\n*** port 1 (~ port 2)\n\n");
    printf("%s\n", RS3_packet_to_string(p12_1));
    printf("%s\n", RS3_key_hash_output_to_string(o12_1));

    printf("\n*** port 2 (~ port 1)\n\n");
    printf("%s\n", RS3_packet_to_string(p12_2));
    printf("%s\n", RS3_key_hash_output_to_string(o12_2));

    if (o12_1 != o12_2) {
      printf("Failed! %u != %u. Exiting.\n", o12_1, o12_2);
      exit(1);
    }
  }
}

int main() {
  RS3_status_t status;
  RS3_cfg_t cfg;
  RS3_key_t keys[2];

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 2);

  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV4_TCP);

  status = RS3_keys_fit_cnstrs(cfg, &mk_p_cnstrs, keys);

  validate(cfg, keys[0], keys[1]);

  printf("%s\n", RS3_cfg_to_string(cfg));
  printf("%s\n", RS3_status_to_string(status));

  if (status == RS3_STATUS_SUCCESS) {
    printf("result:\n%s\n", RS3_key_to_string(keys[0]));
    printf("result:\n%s\n", RS3_key_to_string(keys[1]));
  }

  RS3_cfg_delete(cfg);
}
