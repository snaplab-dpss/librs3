#include "config.h"
#include "../include/rs3.h"
#include "hash.h"
#include "packet.h"
#include "printer.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX(x, y) ((x) >= (y) ? (x) : (y))

void exitf(const char *message) {
  fprintf(stderr, "BUG: %s.\n", message);
  exit(0);
}

void error_handler(Z3_context c, Z3_error_code e) {
  fprintf(stderr, "Error code: %d\n", e);
  if (e == Z3_EXCEPTION)
    fprintf(stderr, "Error msg : %s\n", Z3_get_error_msg(c, e));
  exitf("incorrect use of Z3");
}

Z3_context mk_context_custom(Z3_config cfg, Z3_error_handler err) {
  Z3_context ctx;

  Z3_set_param_value(cfg, "model", "true");

#if DEBUG
  Z3_set_param_value(cfg, "unsat_core", "true");
#endif

  ctx = Z3_mk_context(cfg);

  Z3_set_error_handler(ctx, err);

  return ctx;
}

Z3_context mk_context() {
  Z3_config cfg;
  Z3_context ctx;

  cfg = Z3_mk_config();
  Z3_set_param_value(cfg, "MODEL", "true");

  ctx = mk_context_custom(cfg, error_handler);
  Z3_del_config(cfg);

  return ctx;
}

void RS3_cfg_init(RS3_cfg_t *cfg) {
  *cfg = (RS3_cfg_t)malloc(sizeof(__RS3_cfg_t));

  (*cfg)->loaded_opts = NULL;
  (*cfg)->n_loaded_opts = 0;
  (*cfg)->skew_analysis = true;
  (*cfg)->n_procs = 0;
  (*cfg)->ctx = mk_context();

  (*cfg)->skew_analysis_params.pcap_fname = NULL;
  (*cfg)->skew_analysis_params.time_limit = -1;

  (*cfg)->n_keys = 1;
}

RS3_status_t RS3_cfg_set_number_of_keys(out RS3_cfg_t cfg, unsigned n_keys) {
  cfg->n_keys = n_keys;
}

void cfg_del_ctx(RS3_cfg_t cfg) {
  if (cfg->ctx != NULL) {
    Z3_del_context(cfg->ctx);
  }
  cfg->ctx = NULL;
}

void RS3_cfg_delete(RS3_cfg_t cfg) {
  cfg_del_ctx(cfg);

  free(cfg->loaded_opts);

  if (cfg->skew_analysis_params.pcap_fname != NULL)
    free(cfg->skew_analysis_params.pcap_fname);

  free(cfg);
}

bool is_valid_opt(RS3_opt_t opt) {
  switch (opt) {
    case RS3_OPT_GENEVE_OAM:
    case RS3_OPT_VXLAN_GPE_OAM:
    case RS3_OPT_NON_FRAG_IPV4_TCP:
    case RS3_OPT_NON_FRAG_IPV4_UDP:
    case RS3_OPT_NON_FRAG_IPV4_SCTP:
    case RS3_OPT_NON_FRAG_IPV6_TCP:
    case RS3_OPT_NON_FRAG_IPV6_UDP:
    case RS3_OPT_NON_FRAG_IPV6_SCTP:
    case RS3_OPT_NON_FRAG_IPV6:
    case RS3_OPT_FRAG_IPV6:
    case RS3_OPT_ETHERTYPE:
      return true;
  }

  return false;
}

RS3_status_t RS3_opt_to_pfs(RS3_opt_t opt, RS3_pf_t **pfs, unsigned *n_pfs) {
  // TODO: check if is valid opt
  *n_pfs = 0;

  switch (opt) {
    case RS3_OPT_GENEVE_OAM:
    case RS3_OPT_VXLAN_GPE_OAM:
      *n_pfs = 2;
      *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * (*n_pfs));

      (*pfs)[0] = RS3_PF_VXLAN_UDP_OUTER;
      (*pfs)[1] = RS3_PF_VXLAN_VNI;

      break;
    case RS3_OPT_NON_FRAG_IPV4_UDP:
      *n_pfs = 4;
      *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * (*n_pfs));

      (*pfs)[0] = RS3_PF_IPV4_SRC;
      (*pfs)[1] = RS3_PF_IPV4_DST;
      (*pfs)[2] = RS3_PF_UDP_SRC;
      (*pfs)[3] = RS3_PF_UDP_DST;

      break;
    case RS3_OPT_NON_FRAG_IPV4_TCP:
      *n_pfs = 4;
      *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * (*n_pfs));

      (*pfs)[0] = RS3_PF_IPV4_SRC;
      (*pfs)[1] = RS3_PF_IPV4_DST;
      (*pfs)[2] = RS3_PF_TCP_SRC;
      (*pfs)[3] = RS3_PF_TCP_DST;

      break;
    case RS3_OPT_NON_FRAG_IPV4_SCTP:
      *n_pfs = 5;
      *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * (*n_pfs));

      (*pfs)[0] = RS3_PF_IPV4_SRC;
      (*pfs)[1] = RS3_PF_IPV4_DST;
      (*pfs)[2] = RS3_PF_SCTP_SRC;
      (*pfs)[3] = RS3_PF_SCTP_DST;
      (*pfs)[4] = RS3_PF_SCTP_V_TAG;

      break;
    case RS3_OPT_NON_FRAG_IPV6_UDP:
      *n_pfs = 4;
      *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * (*n_pfs));

      (*pfs)[0] = RS3_PF_IPV6_SRC;
      (*pfs)[1] = RS3_PF_IPV6_DST;
      (*pfs)[2] = RS3_PF_UDP_SRC;
      (*pfs)[3] = RS3_PF_UDP_DST;

      break;
    case RS3_OPT_NON_FRAG_IPV6_TCP:
      *n_pfs = 4;
      *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * (*n_pfs));

      (*pfs)[0] = RS3_PF_IPV6_SRC;
      (*pfs)[1] = RS3_PF_IPV6_DST;
      (*pfs)[2] = RS3_PF_TCP_SRC;
      (*pfs)[3] = RS3_PF_TCP_DST;

      break;
    case RS3_OPT_NON_FRAG_IPV6_SCTP:
      *n_pfs = 5;
      *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * (*n_pfs));

      (*pfs)[0] = RS3_PF_IPV6_SRC;
      (*pfs)[1] = RS3_PF_IPV6_DST;
      (*pfs)[2] = RS3_PF_SCTP_SRC;
      (*pfs)[3] = RS3_PF_SCTP_DST;
      (*pfs)[4] = RS3_PF_SCTP_V_TAG;

      break;
    case RS3_OPT_NON_FRAG_IPV6:
    case RS3_OPT_FRAG_IPV6:
      *n_pfs = 2;
      *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * (*n_pfs));

      (*pfs)[0] = RS3_PF_IPV6_SRC;
      (*pfs)[1] = RS3_PF_IPV6_DST;

      break;
    case RS3_OPT_ETHERTYPE:
      *n_pfs = 1;
      *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * (*n_pfs));

      (*pfs)[0] = RS3_PF_ETHERTYPE;
  }

  return RS3_STATUS_SUCCESS;
}

bool RS3_cfg_are_compatible_pfs(RS3_cfg_t cfg, RS3_in_cfg_t pfs) {
  for (unsigned iopt = 0; iopt < cfg->n_loaded_opts; iopt++) {
    if ((pfs & cfg->loaded_opts[iopt].pfs) != 0)
      return true;
  }
  return false;
}

RS3_status_t RS3_cfg_load_opt(RS3_cfg_t cfg, RS3_opt_t opt) {
  RS3_status_t s;
  RS3_pf_t *pfs;
  unsigned n_pfs;
  unsigned iopt;

  if (!is_valid_opt(opt))
    return RS3_STATUS_OPT_UNKNOWN;

  iopt = cfg->n_loaded_opts;

  cfg->n_loaded_opts++;
  cfg->loaded_opts = (RS3_loaded_opt_t *)realloc(
      cfg->loaded_opts, sizeof(RS3_loaded_opt_t) * cfg->n_loaded_opts);

  cfg->loaded_opts[iopt].opt = opt;
  cfg->loaded_opts[iopt].pfs = 0;
  cfg->loaded_opts[iopt].sz = 0;

  s = RS3_opt_to_pfs(opt, &pfs, &n_pfs);
  if (s != RS3_STATUS_SUCCESS)
    return s;

  for (unsigned i = 0; i < n_pfs; i++) {
    s = RS3_cfg_load_pf(cfg, iopt, pfs[i]);
    if (s == RS3_STATUS_PF_UNKNOWN) {
      free(pfs);
      return s;
    }
  }

  free(pfs);

  return RS3_STATUS_SUCCESS;
}

bool is_valid_pf(RS3_pf_t pf) {
  return pf >= RS3_FIRST_PF && pf <= RS3_LAST_PF;
}

RS3_status_t RS3_cfg_load_pf(RS3_cfg_t cfg, unsigned iopt, RS3_pf_t pf) {
  RS3_status_t status;

  status = RS3_loaded_opt_check_pf(cfg->loaded_opts[iopt], pf);

  if (status == RS3_STATUS_PF_NOT_LOADED) {
    cfg->loaded_opts[iopt].pfs |= (1 << pf);
    cfg->loaded_opts[iopt].sz += RS3_pf_sz_bits(pf);

    return RS3_STATUS_SUCCESS;
  }

  return status;
}

RS3_status_t RS3_loaded_opt_check_pf(RS3_loaded_opt_t opt, RS3_pf_t pf) {
  if (!is_valid_pf(pf))
    return RS3_STATUS_PF_UNKNOWN;

  return ((opt.pfs >> pf) & 1) ? RS3_STATUS_PF_LOADED
                               : RS3_STATUS_PF_NOT_LOADED;
}

unsigned RS3_cfg_max_in_sz(RS3_cfg_t cfg) {
  unsigned max_sz;

  max_sz = 0;

  for (unsigned iopt = 0; iopt < cfg->n_loaded_opts; iopt++)
    max_sz = MAX(max_sz, cfg->loaded_opts[iopt].sz);

  return max_sz;
}

typedef struct {
  RS3_opt_t opt;

  RS3_pf_t *missing;
  size_t missing_sz;

  RS3_pf_t *excess;
  size_t excess_sz;
} opt_pfs_match_t;

opt_pfs_match_t build_opt_pfs_match() {
  opt_pfs_match_t report;

  report.excess = NULL;
  report.excess_sz = 0;

  report.missing = NULL;
  report.missing_sz = 0;

  return report;
}

int cmp_opt_pfs_match(opt_pfs_match_t opm1, opt_pfs_match_t opm2) {

  if (opm1.missing_sz < opm2.missing_sz)
    return 1;
  if (opm1.missing_sz > opm2.missing_sz)
    return -1;

  // opm1.missing_sz is equal to opm2.missing_sz

  if (opm1.excess_sz < opm2.excess_sz)
    return 1;
  if (opm1.excess_sz > opm2.excess_sz)
    return -1;

  // opm1.excess_sz is equal to opm2.excess_sz

  return 0;
}

void opt_cmp_pfs(RS3_opt_t opt, RS3_pf_t *pfs, size_t pfs_sz,
                 opt_pfs_match_t *report) {
  RS3_pf_t *opt_pfs;
  unsigned opt_pfs_sz;

  if (report->missing_sz > 0)
    free(report->missing);
  if (report->excess_sz > 0)
    free(report->excess);

  *report = build_opt_pfs_match();
  report->opt = opt;

  if (pfs_sz == 0)
    return;

  RS3_opt_to_pfs(opt, &opt_pfs, &opt_pfs_sz);

  for (unsigned i = 0; i < pfs_sz; i++) {
    if (!find((void *)(pfs + i), (void *)opt_pfs, opt_pfs_sz,
              sizeof(RS3_pf_t))) {
      report->missing_sz++;
      report->missing = (RS3_pf_t *)realloc(
          report->missing, sizeof(RS3_pf_t) * report->missing_sz);
      report->missing[report->missing_sz - 1] = pfs[i];
    }
  }

  for (unsigned i = 0; i < opt_pfs_sz; i++) {
    if (!find((void *)(opt_pfs + i), (void *)pfs, pfs_sz, sizeof(RS3_pf_t))) {
      report->excess_sz++;
      report->excess = (RS3_pf_t *)realloc(
          report->excess, sizeof(RS3_pf_t) * report->excess_sz);
      report->excess[report->excess_sz - 1] = opt_pfs[i];
    }
  }

  free(opt_pfs);
}

bool opt_array_constains(RS3_opt_t *arr, size_t sz, RS3_opt_t opt) {
  for (unsigned i = 0; i < sz; i++)
    if (arr[i] == opt)
      return true;
  return false;
}

RS3_status_t RS3_opts_from_pfs(RS3_pf_t *_pfs, size_t pfs_sz,
                               out RS3_opt_t **opts, out size_t *opts_sz) {
  RS3_status_t status;
  RS3_opt_t opt;
  opt_pfs_match_t *reports;
  size_t reports_sz;
  bool change;

  *opts = NULL;
  *opts_sz = 0;

  reports_sz = RS3_LAST_OPT - RS3_FIRST_OPT + 1;
  reports = (opt_pfs_match_t *)malloc(sizeof(opt_pfs_match_t) * reports_sz);

  // create a copy first
  RS3_pf_t *pfs = (RS3_pf_t *)malloc(sizeof(RS3_pf_t) * pfs_sz);
  memcpy(pfs, _pfs, sizeof(RS3_pf_t) * pfs_sz);

  remove_dup((void **)&pfs, &pfs_sz, sizeof(RS3_pf_t));

  for (unsigned ipf = 0; ipf < pfs_sz; ipf++) {
    if (!is_valid_pf(pfs[ipf]))
      return RS3_STATUS_PF_UNKNOWN;
  }

  for (unsigned iopt = RS3_FIRST_OPT; iopt <= RS3_LAST_OPT; iopt++) {
    opt = (RS3_opt_t)iopt;
    reports[iopt - RS3_FIRST_OPT] = build_opt_pfs_match();
    opt_cmp_pfs(opt, pfs, pfs_sz, reports + iopt - RS3_FIRST_OPT);
  }

  // bubble sort yay!
  change = true;
  while (change) {
    change = false;

    for (unsigned i = 0; i < reports_sz - 1; i++) {
      if (cmp_opt_pfs_match(reports[i], reports[i + 1]) < 0) {
        opt_pfs_match_t tmp = reports[i + 1];
        reports[i + 1] = reports[i];
        reports[i] = tmp;

        change = true;
      }
    }
  }

  if (reports[0].missing_sz == pfs_sz) {
    DEBUG_LOG("FAILED: no set of opts for given pfs\n");
    status = RS3_STATUS_BAD_SOLUTION;
  } else {
    for (unsigned i = 0; i < reports_sz; i++) {
      if ((cmp_opt_pfs_match(reports[0], reports[i]) != 0) ||
          (opt_array_constains(*opts, *opts_sz, reports[i].opt)))
        continue;

      (*opts_sz)++;
      *opts = (RS3_opt_t *)realloc(*opts, sizeof(RS3_opt_t) * (*opts_sz));
      (*opts)[(*opts_sz) - 1] = reports[i].opt;
    }

    if (reports[0].missing_sz == 0) {
      status = RS3_STATUS_SUCCESS;
    } else {
      RS3_opt_t *missing_opts;
      size_t missing_opts_sz;

      status = RS3_opts_from_pfs(reports[0].missing, reports[0].missing_sz,
                                 &missing_opts, &missing_opts_sz);

      for (unsigned i = 0; i < missing_opts_sz; i++) {
        if (opt_array_constains(*opts, *opts_sz, reports[i].opt))
          continue;

        (*opts_sz)++;
        *opts = (RS3_opt_t *)realloc(*opts, sizeof(RS3_opt_t) * (*opts_sz));
        (*opts)[(*opts_sz) - 1] = missing_opts[i];
      }

      if (missing_opts_sz)
        free(missing_opts);
    }
  }

  for (unsigned i = 0; i < reports_sz; i++) {
    if (reports[i].missing_sz > 0)
      free(reports[i].missing);
    if (reports[i].excess_sz > 0)
      free(reports[i].excess);
  }

  free(reports);
  free(pfs);

  return status;
}

void RS3_cfg_set_user_data(out RS3_cfg_t cfg, void *data) {
  cfg->user_data = data;
}

void *RS3_cfg_get_user_data(RS3_cfg_t cfg) { return cfg->user_data; }

Z3_context RS3_cfg_get_z3_context(RS3_cfg_t cfg) { return cfg->ctx; }

RS3_status_t RS3_cfg_set_skew_analysis(out RS3_cfg_t cfg, bool skew_analysis) {
  cfg->skew_analysis = skew_analysis;

  if (!skew_analysis) {
    cfg->n_procs = 1;
  }

  return RS3_STATUS_SUCCESS;
}

RS3_status_t RS3_cfg_set_number_of_processes(out RS3_cfg_t cfg, int n_procs) {
  if (!cfg->skew_analysis) {
    return RS3_STATUS_NOP;
  }

  cfg->n_procs = n_procs;
}

unsigned RS3_cfg_get_number_of_keys(RS3_cfg_t cfg) { return cfg->n_keys; }

RS3_status_t
RS3_cfg_set_skew_analysis_parameters(out RS3_cfg_t cfg,
                                     RS3_skew_analysis_params_t params) {
  if (!cfg->skew_analysis) {
    return RS3_STATUS_NOP;
  }

  if (params.pcap_fname != NULL && access(params.pcap_fname, F_OK) == -1) {
    return RS3_STATUS_IO_ERROR;
  }

  cfg->skew_analysis_params = params;
}
