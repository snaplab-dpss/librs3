#include <rs3.h>

Z3_ast mk_p_cnstrs(RS3_cfg_t cfg, RS3_packet_ast_t p1, RS3_packet_ast_t p2) {
  return NULL;
}

int main() {
  RS3_cfg_t cfg;
  RS3_key_t k;
  RS3_status_t status;

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 1);
  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV4_TCP);
  RS3_cfg_set_skew_analysis(cfg, false);

  status = RS3_keys_fit_cnstrs(cfg, &mk_p_cnstrs, &k);

  printf("%s\n", RS3_cfg_to_string(cfg));
  printf("%s\n", RS3_status_to_string(status));

  RS3_cfg_delete(cfg);
}
