/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define SNMPV3_ENGINEID_MAX 32
#define SNMPV3_SALT_MAX 752

typedef struct hmac_md5_tmp
{
  u32 idx;
  md5_ctx_t ctx;

} hmac_md5_tmp_t;

typedef struct snmpv3
{
  u32 salt_buf[SNMPV3_SALT_MAX];
  u32 salt_len;

  u8  engineID_buf[SNMPV3_ENGINEID_MAX];
  u32 engineID_len;

  u8 packet_number[8+1];

} snmpv3_t;

KERNEL_FQ void m25100_init (KERN_ATTR_TMPS_ESALT (hmac_md5_tmp_t, snmpv3_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const global u8 *pw_buf = (global u8 *) pws[gid].i;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * authkey
   */

  u32 idx = 0;

  u32 buf[32] = { 0 };

  u8 *tmp_buf = (u8 *) buf;

  md5_ctx_t ctx;

  md5_init (&ctx);

  for (int i = 0; i < 64; i++)
  {
    tmp_buf[i] = pw_buf[idx++];

    if (idx >= pw_len) idx = 0;
  }

  md5_update (&ctx, buf, 64);

  tmps[gid].idx = idx;
  tmps[gid].ctx = ctx;
}

KERNEL_FQ void m25100_loop (KERN_ATTR_TMPS_ESALT (hmac_md5_tmp_t, snmpv3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const global u8 *pw_buf = (global u8 *) pws[gid].i;

  const u32 pw_len = pws[gid].pw_len;

  u32 idx = tmps[gid].idx;

  u32 buf[32] = { 0 };

  u8 *tmp_buf = (u8 *) buf;

  md5_ctx_t ctx = tmps[gid].ctx;

  for (u32 j = 0; j < loop_cnt; j++)
  {
    for (int i = 0; i < 64; i++)
    {
      tmp_buf[i] = pw_buf[idx++];

      if (idx >= pw_len) idx = 0;
    }

    md5_update (&ctx, buf, 64);
  }

  tmps[gid].idx = idx;
  tmps[gid].ctx = ctx;
}

KERNEL_FQ void m25100_comp (KERN_ATTR_TMPS_ESALT (hmac_md5_tmp_t, snmpv3_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const global u8 *engineID_buf = esalt_bufs[DIGESTS_OFFSET].engineID_buf;

  u32 engineID_len = esalt_bufs[DIGESTS_OFFSET].engineID_len;

  md5_ctx_t ctx = tmps[gid].ctx;

  md5_final (&ctx);

  const u32 h[4] = {
    hc_swap32_S (ctx.h[0]),
    hc_swap32_S (ctx.h[1]),
    hc_swap32_S (ctx.h[2]),
    hc_swap32_S (ctx.h[3])
  };

  u32 tmp_buf[32] = { 0 };

  u8 *buf = (u8 *) tmp_buf;

  buf[ 3] = v8a_from_v32_S (h[0]);
  buf[ 2] = v8b_from_v32_S (h[0]);
  buf[ 1] = v8c_from_v32_S (h[0]);
  buf[ 0] = v8d_from_v32_S (h[0]);

  buf[ 7] = v8a_from_v32_S (h[1]);
  buf[ 6] = v8b_from_v32_S (h[1]);
  buf[ 5] = v8c_from_v32_S (h[1]);
  buf[ 4] = v8d_from_v32_S (h[1]);

  buf[11] = v8a_from_v32_S (h[2]);
  buf[10] = v8b_from_v32_S (h[2]);
  buf[ 9] = v8c_from_v32_S (h[2]);
  buf[ 8] = v8d_from_v32_S (h[2]);

  buf[15] = v8a_from_v32_S (h[3]);
  buf[14] = v8b_from_v32_S (h[3]);
  buf[13] = v8c_from_v32_S (h[3]);
  buf[12] = v8d_from_v32_S (h[3]);

  u32 i = 16;
  u32 j;

  for (j = 0; j < engineID_len; j++)
  {
    buf[i++] = engineID_buf[j];
  }

  for (j = 0; j < 16; j++)
  {
    buf[i++] = buf[j];
  }

  md5_init (&ctx);

  md5_update (&ctx, tmp_buf, i);

  md5_final (&ctx);

  u32 key[16] = { 0 };

  key[0] = ctx.h[0];
  key[1] = ctx.h[1];
  key[2] = ctx.h[2];
  key[3] = ctx.h[3];

  md5_hmac_ctx_t hmac_ctx;

  md5_hmac_init (&hmac_ctx, key, 16);

  md5_hmac_update_global (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET].salt_buf, esalt_bufs[DIGESTS_OFFSET].salt_len);

  md5_hmac_final (&hmac_ctx);

  const u32 r0 = hmac_ctx.opad.h[DGST_R0];
  const u32 r1 = hmac_ctx.opad.h[DGST_R1];
  const u32 r2 = hmac_ctx.opad.h[DGST_R2];

  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
