#include <rs3.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  RS3_cfg_t cfg;
  RS3_key_t k;
  RS3_status_t status;
  RS3_stats_t stats;
  char pcap[50];
  RS3_packet_t *packets;
  int n_packets;

  sprintf(pcap, "/home/fcp/librs3/pcap/zipf.pcap");

  RS3_cfg_init(&cfg);
  RS3_cfg_set_number_of_keys(cfg, 1);

  RS3_cfg_load_opt(cfg, RS3_OPT_NON_FRAG_IPV4_TCP);

  status = RS3_packets_parse(cfg, pcap, &packets, &n_packets);

  printf("%s\n", RS3_cfg_to_string(cfg));
  printf("Status: %s\n", RS3_status_to_string(status));

  for (unsigned i = 0; i < n_packets; i++)
    printf("packet %u\n%s\n", i, RS3_packet_to_string(packets[i]));

  RS3_key_rand(cfg, k);
  printf("Key:\n%s\n", RS3_key_to_string(k));

  RS3_stats_from_packets(k, packets, n_packets, &stats);
  printf("Stats:\n%s\n", RS3_stats_to_string(stats));

  free(packets);

  RS3_cfg_delete(cfg);
}
