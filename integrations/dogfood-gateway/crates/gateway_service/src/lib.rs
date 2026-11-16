//! Safe RPC Edge Gateway wrapper over the AIL-verified `#![no_std]` kernel.

use gateway_kernel::{
    decode_mrnt_rpc_frame, encode_mrnt_rpc_frame, gateway_charge_and_limit, rate_decision_fee,
    BucketState, RateDecision, RpcFrameDecoded,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayPolicy {
    pub rate_per_sec: u64,
    pub cap: u64,
    pub cost_per_rpc: u64,
    pub fee_bps: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayError {
    TruncatedFrame,
    BadMagic,
    UnsupportedVersion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessedRpc {
    pub seq: u64,
    pub flags: u64,
    pub notional: u64,
    pub decision: RateDecision,
    pub response_frame: [u8; 32],
}

/// Decode an inbound `"MRNT"` wire frame, apply token-bucket rate limiting + 128-bit fee metering,
/// and encode the outbound 32-byte `"MRNT"` wire response frame.
pub fn handle_rpc_frame(
    bucket: &mut BucketState,
    now_ms: u64,
    policy: &GatewayPolicy,
    inbound: &[u8],
) -> Result<ProcessedRpc, GatewayError> {
    let decoded = decode_mrnt_rpc_frame(inbound.len() as u64, inbound);
    let (flags, seq, notional) = match decoded {
        RpcFrameDecoded::RpcOk(flags, seq, notional, _client_fee) => (flags, seq, notional),
        RpcFrameDecoded::RpcErr(1) => return Err(GatewayError::TruncatedFrame),
        RpcFrameDecoded::RpcErr(2) => return Err(GatewayError::BadMagic),
        RpcFrameDecoded::RpcErr(_) => return Err(GatewayError::UnsupportedVersion),
    };

    let decision = gateway_charge_and_limit(
        *bucket,
        now_ms,
        policy.rate_per_sec.min(100_000),
        policy.cap.min(1_000_000),
        policy.cost_per_rpc.min(1_000_000),
        notional,
        policy.fee_bps.min(10_000),
    );

    let fee = rate_decision_fee(decision);
    let mut out_flags = flags;
    if let RateDecision::Allowed(next_bucket, _charged) = decision {
        *bucket = next_bucket;
        out_flags |= 0x80; // accepted response flag bit
    }

    let mut response_frame = [0u8; 32];
    let written = encode_mrnt_rpc_frame(
        response_frame.len() as u64,
        &mut response_frame,
        out_flags,
        seq,
        notional,
        fee,
    );
    debug_assert_eq!(written, 32);

    Ok(ProcessedRpc {
        seq,
        flags: out_flags,
        notional,
        decision,
        response_frame,
    })
}

pub fn encode_request_frame(flags: u64, seq: u64, notional: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    encode_mrnt_rpc_frame(
        buf.len() as u64,
        &mut buf,
        flags & 0xFF,
        seq & 0xFFFF_FFFF,
        notional,
        0,
    );
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> GatewayPolicy {
        GatewayPolicy {
            rate_per_sec: 10,
            cap: 20,
            cost_per_rpc: 10,
            fee_bps: 25,
        }
    }

    #[test]
    fn roundtrip_and_large_notional_128bit_fee() {
        let mut bucket = BucketState {
            tokens: 20,
            last_ms: 1000,
        };
        let notional = 1_000_000_000_000_000_000u64; // 10^18 -> 10^18 * 25 overflows u64, needs u128!
        let req = encode_request_frame(0x03, 42, notional);
        let resp = handle_rpc_frame(&mut bucket, 1000, &default_policy(), &req).expect("valid frame");

        match resp.decision {
            RateDecision::Allowed(next_b, fee) => {
                assert_eq!(fee, 2_500_000_000_000_000u64);
                assert_eq!(next_b.tokens, 10);
                assert_eq!(bucket.tokens, 10);
            }
            other => panic!("expected Allowed, got {other:?}"),
        }

        // Decode response wire frame back via verified kernel decoder
        let decoded = decode_mrnt_rpc_frame(resp.response_frame.len() as u64, &resp.response_frame);
        match decoded {
            RpcFrameDecoded::RpcOk(flags, seq, out_notional, out_fee) => {
                assert_eq!(flags, 0x83);
                assert_eq!(seq, 42);
                assert_eq!(out_notional, notional);
                assert_eq!(out_fee, 2_500_000_000_000_000u64);
            }
            other => panic!("expected RpcOk, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_exhaustion_and_refill_recovery() {
        let policy = default_policy();
        let mut bucket = BucketState {
            tokens: 15,
            last_ms: 1000,
        };

        // 1st RPC consumes 10 tokens -> 5 left
        let req1 = encode_request_frame(1, 1, 10_000);
        let r1 = handle_rpc_frame(&mut bucket, 1000, &policy, &req1).unwrap();
        assert!(matches!(r1.decision, RateDecision::Allowed(_, 25)));
        assert_eq!(bucket.tokens, 5);

        // 2nd RPC at same timestamp has only 5 tokens < cost 10 -> Rejected
        let req2 = encode_request_frame(1, 2, 10_000);
        let r2 = handle_rpc_frame(&mut bucket, 1000, &policy, &req2).unwrap();
        assert!(matches!(r2.decision, RateDecision::Rejected(1, 1)));
        assert_eq!(bucket.tokens, 5);

        // Advance clock by 1000ms -> refills +10 tokens (total 15 >= 10) -> Allowed!
        let req3 = encode_request_frame(1, 3, 10_000);
        let r3 = handle_rpc_frame(&mut bucket, 2000, &policy, &req3).unwrap();
        assert!(matches!(r3.decision, RateDecision::Allowed(_, 25)));
        assert_eq!(bucket.tokens, 5);
    }

    #[test]
    fn rejects_malformed_or_truncated_frames() {
        let policy = default_policy();
        let mut bucket = BucketState {
            tokens: 20,
            last_ms: 0,
        };

        assert_eq!(
            handle_rpc_frame(&mut bucket, 10, &policy, &[0u8; 16]),
            Err(GatewayError::TruncatedFrame)
        );

        let mut bad_magic = encode_request_frame(0, 1, 100);
        bad_magic[0] = b'X';
        assert_eq!(
            handle_rpc_frame(&mut bucket, 10, &policy, &bad_magic),
            Err(GatewayError::BadMagic)
        );

        let mut bad_ver = encode_request_frame(0, 1, 100);
        bad_ver[4] = 9;
        assert_eq!(
            handle_rpc_frame(&mut bucket, 10, &policy, &bad_ver),
            Err(GatewayError::UnsupportedVersion)
        );
    }
}
