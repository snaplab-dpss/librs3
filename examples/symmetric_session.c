#include <rs3.h>

int main() {
  RS3_status_t status;
  RS3_cfg_t cfg;
  RS3_key_t k;

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 1);

  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV4_TCP);

  status = RS3_keys_fit_cnstrs(cfg, &RS3_cnstr_symmetric_tcp_ip, &k);

  printf("%s\n", RS3_cfg_to_string(cfg));
  printf("%s\n", RS3_status_to_string(status));

  if (status == RS3_STATUS_SUCCESS)
    printf("result:\n%s\n", RS3_key_to_string(k));

  RS3_cfg_delete(cfg);
}
