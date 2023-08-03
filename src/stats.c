#include "../include/rs3.h"
#include "hash.h"
#include "printer.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>

void RS3_stats_init(RS3_cfg_t cfg, out RS3_stats_t *stats) {
  stats->cfg = cfg;
  stats->used_lut_entries = 0;
}

void RS3_stats_reset(RS3_cfg_t cfg, out RS3_stats_t *stats) {
  RS3_stats_init(cfg, stats);
}

RS3_status_t RS3_stats_from_packets(RS3_key_t key, RS3_packet_t *packets,
                                    int n_packets, out RS3_stats_t *stats) {
  RS3_packet_t packet;
  RS3_key_hash_out_t output;

  uint32_t lut_index;
  uint64_t deviation; // uint64_t to capture negative and positive deviations
                      // between the LUT index and its avergage.

  bool lut[LUT_SIZE];
  memset(lut, 0, LUT_SIZE);

  for (unsigned ipacket = 0; ipacket < n_packets; ipacket++) {
    packet = packets[ipacket];
    RS3_key_hash(stats->cfg, key, packet, &output);

    lut_index = HASH_MASK(output);

    if (!lut[lut_index]) {
      stats->used_lut_entries++;
      lut[lut_index] = true;
    }
  }

  return RS3_STATUS_SUCCESS;
}

bool RS3_stats_eval(RS3_cfg_t cfg, RS3_key_t key, out RS3_stats_t *stats) {
  RS3_key_t rand_key;
  RS3_stats_t rand_key_stats;
  RS3_packet_t *packets;
  RS3_status_t status;
  int n_packets;

  RS3_stats_reset(cfg, stats);

  if (cfg->skew_analysis_params.pcap_fname != NULL) {
    status = RS3_packets_parse(cfg, cfg->skew_analysis_params.pcap_fname,
                               &packets, &n_packets);
    if (status != RS3_STATUS_SUCCESS) {
      DEBUG_PLOG("Key evaluation failed: %s\n", RS3_status_to_string(status));
      free(packets);
      return false;
    }
  } else {
    n_packets = STATS;
    status = RS3_packets_rand(cfg, n_packets, &packets);
    if (status != RS3_STATUS_SUCCESS) {
      DEBUG_PLOG("Key evaluation failed: %s\n", RS3_status_to_string(status));
      free(packets);
      return false;
    }
  }

  status = RS3_stats_from_packets(key, packets, n_packets, stats);
  if (status != RS3_STATUS_SUCCESS) {
    DEBUG_PLOG("Key evaluation failed: %s\n", RS3_status_to_string(status));
    free(packets);
    return false;
  }

  free(packets);

  int n_cores = cfg->skew_analysis_params.n_cores > 0
                    ? cfg->skew_analysis_params.n_cores
                    : DEFAULT_NUM_CORES_SKEW_ANALYSIS;

  bool pass = stats->used_lut_entries >= n_cores;

  DEBUG_PLOG("Key evaluation:\n%s\n%sPass: %d\n", RS3_key_to_string(key),
             RS3_stats_to_string(*stats), pass);

  return pass;
}
