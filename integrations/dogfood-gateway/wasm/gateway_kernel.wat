(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))
  (func $__ail_alloc (export "__ail_alloc") (param $size i32) (result i32)
    (local $aligned i64) (local $ptr i32) (local $needed_end i64) (local $mem_bytes i64) (local $needed_pages i32)
    local.get 0
    i64.extend_i32_u
    i64.const 7
    i64.add
    i64.const -8
    i64.and
    local.set 1
    global.get 0
    local.tee 2
    i64.extend_i32_u
    local.get 1
    i64.add
    local.set 3
    memory.size
    i64.extend_i32_u
    i64.const 16
    i64.shl
    local.set 4
    local.get 3
    local.get 4
    i64.gt_u
    if
      local.get 3
      local.get 4
      i64.sub
      i64.const 65535
      i64.add
      i64.const 16
      i64.shr_u
      i32.wrap_i64
      local.set 5
      local.get 5
      memory.grow
      i32.const -1
      i32.eq
      if
        unreachable
      end
    end
    local.get 3
    i32.wrap_i64
    global.set 0
    local.get 2
  )
  (func $__ail_heap_mark (export "__ail_heap_mark") (result i32)
    global.get 0
  )
  (func $__ail_heap_reset (export "__ail_heap_reset") (param $mark i32)
    local.get 0
    global.set 0
  )
  (func $__ail_mul_div_u64 (param $a i64) (param $b i64) (param $d i64) (param $is_ceil i32) (result i64)
    (local $a_lo i64) (local $a_hi i64) (local $b_lo i64) (local $b_hi i64) (local $p0 i64) (local $p1 i64) (local $p2 i64) (local $p3 i64) (local $mid i64) (local $lo i64) (local $hi i64) (local $nlo i64) (local $rem i64) (local $quot i64) (local $msb i64) (local $step i32)
    local.get 0
    i64.const 4294967295
    i64.and
    local.set 4
    local.get 0
    i64.const 32
    i64.shr_u
    local.set 5
    local.get 1
    i64.const 4294967295
    i64.and
    local.set 6
    local.get 1
    i64.const 32
    i64.shr_u
    local.set 7
    local.get 4
    local.get 6
    i64.mul
    local.set 8
    local.get 4
    local.get 7
    i64.mul
    local.set 9
    local.get 5
    local.get 6
    i64.mul
    local.set 10
    local.get 5
    local.get 7
    i64.mul
    local.set 11
    local.get 8
    i64.const 32
    i64.shr_u
    local.get 9
    i64.const 4294967295
    i64.and
    i64.add
    local.get 10
    i64.const 4294967295
    i64.and
    i64.add
    local.set 12
    local.get 8
    i64.const 4294967295
    i64.and
    local.get 12
    i64.const 32
    i64.shl
    i64.or
    local.set 13
    local.get 11
    local.get 9
    i64.const 32
    i64.shr_u
    i64.add
    local.get 10
    i64.const 32
    i64.shr_u
    i64.add
    local.get 12
    i64.const 32
    i64.shr_u
    i64.add
    local.set 14
    local.get 3
    if
      local.get 13
      local.get 2
      i64.const 1
      i64.sub
      i64.add
      local.tee 15
      local.get 13
      i64.lt_u
      if
        local.get 14
        i64.const 1
        i64.add
        local.set 14
      end
      local.get 15
      local.set 13
    end
    local.get 14
    i64.eqz
    if
      local.get 13
      local.get 2
      i64.div_u
      return
    end
    local.get 14
    local.get 2
    i64.rem_u
    local.set 16
    i64.const 0
    local.set 17
    i32.const 0
    local.set 19
    block
      loop
        local.get 19
        i32.const 64
        i32.ge_u
        br_if 1
        local.get 16
        i64.const 63
        i64.shr_u
        local.set 18
        local.get 16
        i64.const 1
        i64.shl
        local.get 13
        i64.const 63
        i64.shr_u
        i64.or
        local.set 16
        local.get 13
        i64.const 1
        i64.shl
        local.set 13
        local.get 17
        i64.const 1
        i64.shl
        local.set 17
        local.get 18
        i64.const 0
        i64.ne
        local.get 16
        local.get 2
        i64.ge_u
        i32.or
        if
          local.get 16
          local.get 2
          i64.sub
          local.set 16
          local.get 17
          i64.const 1
          i64.or
          local.set 17
        end
        local.get 19
        i32.const 1
        i32.add
        local.set 19
        br 0
      end
    end
    local.get 17
  )
  (func $mul_bps_floor (export "mul_bps_floor") (param $amount i64) (param $bps i64) (result i64)
    local.get 0
    local.get 1
    i64.mul
    i64.const 10000
    i64.div_u
  )
  (func $net_after_bps_fee (export "net_after_bps_fee") (param $gross i64) (param $fee_bps i64) (result i64)
    (local $fee_1 i64)
    local.get 0
    local.get 1
    i64.mul
    i64.const 10000
    i64.div_u
    local.set 2
    local.get 0
    local.get 2
    i64.sub
  )
  (func $maker_rebate_capped (export "maker_rebate_capped") (param $notional i64) (param $rebate_bps i64) (param $max_rebate i64) (result i64)
    (local $raw_1 i64) (local $mm_a_2 i64) (local $mm_b_3 i64)
    local.get 0
    local.get 1
    i64.mul
    i64.const 10000
    i64.div_u
    local.set 3
    local.get 3
    local.set 4
    local.get 2
    local.set 5
    local.get 4
    local.get 5
    local.get 4
    local.get 5
    i64.lt_u
    select
  )
  (func $quote_spread_bps (export "quote_spread_bps") (param $q i32) (result i64)
    (local $b_1 i64) (local $a_2 i64)
    local.get 0
    i64.load align=8
    local.set 1
    local.get 0
    i64.load offset=8 align=8
    local.set 2
    local.get 2
    local.get 1
    i64.sub
    i64.const 10000
    i64.mul
    local.get 1
    i64.div_u
  )
  (func $mul_bps_wide_u64 (export "mul_bps_wide_u64") (param $amount i64) (param $bps i64) (result i64)
    local.get 0
    local.get 1
    i64.const 10000
    i32.const 0
    call $__ail_mul_div_u64
  )
  (func $mul_bps_ceil_u64 (export "mul_bps_ceil_u64") (param $amount i64) (param $bps i64) (result i64)
    local.get 0
    local.get 1
    i64.const 10000
    i32.const 1
    call $__ail_mul_div_u64
  )
  (func $write_ail_magic (export "write_ail_magic") (param $n i64) (param $buf i32) (result i64)
    (local $w0_1 i64) (local $w1_2 i64) (local $w2_3 i64) (local $w3_4 i64)
    local.get 1
    i64.const 0
    i32.wrap_i64
    i32.add
    i64.const 65
    i64.store8 align=1
    i64.const 1
    local.set 2
    local.get 1
    i64.const 1
    i32.wrap_i64
    i32.add
    i64.const 73
    i64.store8 align=1
    i64.const 1
    local.set 3
    local.get 1
    i64.const 2
    i32.wrap_i64
    i32.add
    i64.const 76
    i64.store8 align=1
    i64.const 1
    local.set 4
    local.get 1
    i64.const 3
    i32.wrap_i64
    i32.add
    i64.const 49
    i64.store8 align=1
    i64.const 1
    local.set 5
    local.get 2
    local.get 3
    i64.add
    local.get 4
    local.get 5
    i64.add
    i64.add
  )
  (func $encode_ail_frame_header (export "encode_ail_frame_header") (param $n i64) (param $buf i32) (param $version i64) (param $flags i64) (param $payload_len i64) (result i64)
    (local $wm_1 i64) (local $wv_2 i64) (local $wf_3 i64) (local $write_u16_be_addr_4 i32) (local $write_u16_be_val_5 i64) (local $wp_6 i64)
    local.get 0
    local.get 1
    call $write_ail_magic
    local.set 5
    local.get 1
    i64.const 4
    i32.wrap_i64
    i32.add
    local.get 2
    i64.store8 align=1
    i64.const 1
    local.set 6
    local.get 1
    i64.const 5
    i32.wrap_i64
    i32.add
    local.get 3
    i64.store8 align=1
    i64.const 1
    local.set 7
    local.get 1
    i64.const 6
    i32.wrap_i64
    i32.add
    local.set 8
    local.get 4
    local.set 9
    local.get 8
    local.get 9
    i64.const 8
    i64.shr_u
    i64.store8 align=1
    local.get 8
    local.get 9
    i64.store8 offset=1 align=1
    i64.const 2
    local.set 10
    local.get 5
    local.get 6
    local.get 7
    local.get 10
    i64.add
    i64.add
    i64.add
  )
  (func $read_payload_u32_le (export "read_payload_u32_le") (param $n i64) (param $buf i32) (result i64)
    local.get 1
    i64.const 8
    i32.wrap_i64
    i32.add
    i64.load32_u align=1
  )
  (func $read_payload_u64_le (export "read_payload_u64_le") (param $n i64) (param $buf i32) (result i64)
    local.get 1
    i64.const 8
    i32.wrap_i64
    i32.add
    i64.load align=1
  )
  (func $write_payload_u64_le (export "write_payload_u64_le") (param $n i64) (param $buf i32) (param $val i64) (result i64)
    local.get 1
    i64.const 8
    i32.wrap_i64
    i32.add
    local.get 2
    i64.store align=1
    i64.const 8
  )
  (func $refill_tokens (export "refill_tokens") (param $cur_tokens i64) (param $last_ms i64) (param $now_ms i64) (param $rate_per_sec i64) (param $cap i64) (result i64)
    (local $mm_a_1 i64) (local $mm_b_2 i64) (local $mm_a_3 i64) (local $mm_b_4 i64) (local $dt_5 i64) (local $added_6 i64) (local $mm_a_7 i64) (local $mm_b_8 i64) (local $base_9 i64) (local $mm_a_10 i64) (local $mm_b_11 i64)
    local.get 2
    local.get 1
    i64.le_u
    if (result i64)
      local.get 0
      local.set 5
      local.get 4
      local.set 6
      local.get 5
      local.get 6
      local.get 5
      local.get 6
      i64.lt_u
      select
    else
      local.get 2
      local.get 1
      i64.sub
      local.set 7
      i64.const 1000000
      local.set 8
      local.get 7
      local.get 8
      local.get 7
      local.get 8
      i64.lt_u
      select
      local.set 9
      local.get 9
      local.get 3
      i64.const 1000
      i32.const 0
      call $__ail_mul_div_u64
      local.set 10
      local.get 0
      local.set 11
      local.get 4
      local.set 12
      local.get 11
      local.get 12
      local.get 11
      local.get 12
      i64.lt_u
      select
      local.set 13
      local.get 4
      local.set 14
      local.get 13
      local.get 10
      i64.add
      local.set 15
      local.get 14
      local.get 15
      local.get 14
      local.get 15
      i64.lt_u
      select
    end
  )
  (func $gateway_charge_and_limit (export "gateway_charge_and_limit") (param $bucket i32) (param $now_ms i64) (param $rate_per_sec i64) (param $cap i64) (param $cost i64) (param $notional i64) (param $fee_bps i64) (result i32)
    (local $cur_1 i64) (local $prev_ms_2 i64) (local $refilled_3 i64) (local $fee_4 i64) (local $mm_a_5 i64) (local $mm_b_6 i64) (local $next_ms_7 i64) (local $BucketState_ptr_8 i32) (local $next_bucket_9 i32) (local $RateDecision_ptr_10 i32) (local $agg_src_11 i32) (local $wait_ms_12 i64) (local $RateDecision_ptr_13 i32)
    local.get 0
    i64.load align=8
    local.set 7
    local.get 0
    i64.load offset=8 align=8
    local.set 8
    local.get 7
    local.get 8
    local.get 1
    local.get 2
    local.get 3
    call $refill_tokens
    local.set 9
    local.get 9
    local.get 4
    i64.ge_u
    if (result i32)
      local.get 5
      local.get 6
      call $mul_bps_ceil_u64
      local.set 10
      local.get 1
      local.set 11
      local.get 8
      local.set 12
      local.get 11
      local.get 12
      local.get 11
      local.get 12
      i64.gt_u
      select
      local.set 13
      i32.const 16
      call $__ail_alloc
      local.set 14
      local.get 14
      local.get 9
      local.get 4
      i64.sub
      i64.store align=8
      local.get 14
      local.get 13
      i64.store offset=8 align=8
      local.get 14
      local.set 15
      i32.const 32
      call $__ail_alloc
      local.set 16
      local.get 16
      i64.const 0
      i64.store align=8
      local.get 15
      local.set 17
      local.get 16
      local.get 17
      i64.load align=8
      i64.store offset=8 align=8
      local.get 16
      local.get 17
      i64.load offset=8 align=8
      i64.store offset=16 align=8
      local.get 16
      local.get 10
      i64.store offset=24 align=8
      local.get 16
    else
      local.get 1
      local.get 8
      i64.lt_u
      if (result i64)
        local.get 8
        local.get 1
        i64.sub
      else
        i64.const 1
      end
      local.set 18
      i32.const 32
      call $__ail_alloc
      local.set 19
      local.get 19
      i64.const 1
      i64.store align=8
      local.get 19
      local.get 18
      i64.store offset=8 align=8
      local.get 19
      i64.const 1
      i64.store offset=16 align=8
      local.get 19
      i64.const 0
      i64.store offset=24 align=8
      local.get 19
    end
  )
  (func $rate_decision_fee (export "rate_decision_fee") (param $d i32) (result i64)
    (local $match_scrut_1 i32) (local $match_tag_2 i32) (local $next_b_3 i32) (local $fee_4 i64) (local $retry_5 i64) (local $reason_6 i64)
    local.get 0
    local.set 1
    local.get 1
    i64.load align=8
    i32.wrap_i64
    local.set 2
    block (result i64)
      block
        block
          local.get 2
          br_table 0 1 0
        end
        local.get 1
        i32.const 8
        i32.add
        local.set 3
        local.get 1
        i64.load offset=24 align=8
        local.set 4
        local.get 4
        br 1
      end
      local.get 1
      i64.load offset=8 align=8
      local.set 5
      local.get 1
      i64.load offset=16 align=8
      local.set 6
      i64.const 0
    end
  )
  (func $encode_mrnt_rpc_frame (export "encode_mrnt_rpc_frame") (param $n i64) (param $buf i32) (param $flags i64) (param $seq i64) (param $notional i64) (param $fee i64) (result i64)
    (local $w0_1 i64) (local $w1_2 i64) (local $w2_3 i64) (local $w3_4 i64) (local $wv_5 i64) (local $wf_6 i64) (local $write_u16_be_addr_7 i32) (local $write_u16_be_val_8 i64) (local $wl_9 i64) (local $ws_10 i64) (local $wr_11 i64) (local $wn_12 i64) (local $wfee_13 i64)
    local.get 1
    i64.const 0
    i32.wrap_i64
    i32.add
    i64.const 77
    i64.store8 align=1
    i64.const 1
    local.set 6
    local.get 1
    i64.const 1
    i32.wrap_i64
    i32.add
    i64.const 82
    i64.store8 align=1
    i64.const 1
    local.set 7
    local.get 1
    i64.const 2
    i32.wrap_i64
    i32.add
    i64.const 78
    i64.store8 align=1
    i64.const 1
    local.set 8
    local.get 1
    i64.const 3
    i32.wrap_i64
    i32.add
    i64.const 84
    i64.store8 align=1
    i64.const 1
    local.set 9
    local.get 1
    i64.const 4
    i32.wrap_i64
    i32.add
    i64.const 1
    i64.store8 align=1
    i64.const 1
    local.set 10
    local.get 1
    i64.const 5
    i32.wrap_i64
    i32.add
    local.get 2
    i64.store8 align=1
    i64.const 1
    local.set 11
    local.get 1
    i64.const 6
    i32.wrap_i64
    i32.add
    local.set 12
    i64.const 24
    local.set 13
    local.get 12
    local.get 13
    i64.const 8
    i64.shr_u
    i64.store8 align=1
    local.get 12
    local.get 13
    i64.store8 offset=1 align=1
    i64.const 2
    local.set 14
    local.get 1
    i64.const 8
    i32.wrap_i64
    i32.add
    local.get 3
    i64.store32 align=1
    i64.const 4
    local.set 15
    local.get 1
    i64.const 12
    i32.wrap_i64
    i32.add
    i64.const 0
    i64.store32 align=1
    i64.const 4
    local.set 16
    local.get 1
    i64.const 16
    i32.wrap_i64
    i32.add
    local.get 4
    i64.store align=1
    i64.const 8
    local.set 17
    local.get 1
    i64.const 24
    i32.wrap_i64
    i32.add
    local.get 5
    i64.store align=1
    i64.const 8
    local.set 18
    local.get 6
    local.get 7
    local.get 8
    local.get 9
    local.get 10
    local.get 11
    local.get 14
    local.get 15
    local.get 16
    local.get 17
    local.get 18
    i64.add
    i64.add
    i64.add
    i64.add
    i64.add
    i64.add
    i64.add
    i64.add
    i64.add
    i64.add
  )
  (func $decode_mrnt_rpc_frame (export "decode_mrnt_rpc_frame") (param $n i64) (param $buf i32) (result i32)
    (local $RpcFrameDecoded_ptr_1 i32) (local $RpcFrameDecoded_ptr_2 i32) (local $ver_3 i64) (local $RpcFrameDecoded_ptr_4 i32) (local $RpcFrameDecoded_ptr_5 i32)
    local.get 0
    i64.const 32
    i64.lt_u
    if (result i32)
      i32.const 40
      call $__ail_alloc
      local.set 2
      local.get 2
      i64.const 1
      i64.store align=8
      local.get 2
      i64.const 1
      i64.store offset=8 align=8
      local.get 2
      i64.const 0
      i64.store offset=16 align=8
      local.get 2
      i64.const 0
      i64.store offset=24 align=8
      local.get 2
      i64.const 0
      i64.store offset=32 align=8
      local.get 2
    else
      local.get 1
      i64.const 0
      i32.wrap_i64
      i32.add
      i32.load align=1
      i32.const 1414419021
      i32.eq
      i64.extend_i32_u
      i64.const 0
      i64.eq
      if (result i32)
        i32.const 40
        call $__ail_alloc
        local.set 3
        local.get 3
        i64.const 1
        i64.store align=8
        local.get 3
        i64.const 2
        i64.store offset=8 align=8
        local.get 3
        i64.const 0
        i64.store offset=16 align=8
        local.get 3
        i64.const 0
        i64.store offset=24 align=8
        local.get 3
        i64.const 0
        i64.store offset=32 align=8
        local.get 3
      else
        local.get 1
        i64.const 4
        i32.wrap_i64
        i32.add
        i64.load8_u align=1
        local.set 4
        local.get 4
        i64.const 1
        i64.ne
        if (result i32)
          i32.const 40
          call $__ail_alloc
          local.set 5
          local.get 5
          i64.const 1
          i64.store align=8
          local.get 5
          i64.const 3
          i64.store offset=8 align=8
          local.get 5
          i64.const 0
          i64.store offset=16 align=8
          local.get 5
          i64.const 0
          i64.store offset=24 align=8
          local.get 5
          i64.const 0
          i64.store offset=32 align=8
          local.get 5
        else
          i32.const 40
          call $__ail_alloc
          local.set 6
          local.get 6
          i64.const 0
          i64.store align=8
          local.get 6
          local.get 1
          i64.const 5
          i32.wrap_i64
          i32.add
          i64.load8_u align=1
          i64.store offset=8 align=8
          local.get 6
          local.get 1
          i64.const 8
          i32.wrap_i64
          i32.add
          i64.load32_u align=1
          i64.store offset=16 align=8
          local.get 6
          local.get 1
          i64.const 16
          i32.wrap_i64
          i32.add
          i64.load align=1
          i64.store offset=24 align=8
          local.get 6
          local.get 1
          i64.const 24
          i32.wrap_i64
          i32.add
          i64.load align=1
          i64.store offset=32 align=8
          local.get 6
        end
      end
    end
  )
)
