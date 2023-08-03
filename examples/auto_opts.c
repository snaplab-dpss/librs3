#include <rs3.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  RS3_opt_t *opts;
  size_t opts_sz;
  RS3_pf_t pfs[10] = { RS3_PF_IPV4_SRC, RS3_PF_IPV4_DST, RS3_PF_TCP_SRC,
                       RS3_PF_TCP_DST,  RS3_PF_UDP_SRC,  RS3_PF_UDP_DST };

  RS3_opts_from_pfs(pfs, 6, &opts, &opts_sz);

  printf("Resulting options:\n");
  for (unsigned i = 0; i < opts_sz; i++)
    printf("%s\n", RS3_opt_to_string(opts[i]));

  free(opts);
}
