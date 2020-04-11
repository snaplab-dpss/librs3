#include <rssks.h>

Z3_ast mk_d_cnstrs(RSSKS_cfg_t rssks_cfg, Z3_context ctx, Z3_ast d1, Z3_ast d2)
{
    Z3_ast d1_ipv4_src;
    Z3_ast d2_ipv4_src;
    Z3_ast eq_src_ip;

    d1_ipv4_src = extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_IPV4_SRC);
    d2_ipv4_src = extract_pf_from_d(rssks_cfg, ctx, d2, RSSKS_PF_IPV4_SRC);

    eq_src_ip   = Z3_mk_eq(ctx, d1_ipv4_src, d2_ipv4_src);

    return Z3_mk_and(ctx, 1, &eq_src_ip);
}

int main () {
    RSSKS_cfg_t cfg;
    RSSKS_key_t k;

    cfg = RSSKS_cfg_init();
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4_TCP);

    find_k(cfg, &mk_d_cnstrs, k);
    print_key(k);
}