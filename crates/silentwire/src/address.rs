//! `no_std` BIP-352 Bech32m address encoder and `v0..=v30` decoder.
//!
//! Enforces Bech32m checksums (`0x2bc830a3`), a 1023-character length cap,
//! single-case strings, and `"sp"` / `"tsp"` HRPs. Version `0` requires an
//! exact 66-byte payload (`B_scan || B_spend`). Versions `1..=30` require at
//! least 66 bytes and retain trailing bytes in `extension_data`. Version `31`
//! is rejected.

use crate::{compressed, point, Error};
use alloc::{string::String, vec::Vec};
use k256::AffinePoint;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const GENERATORS: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

pub const MAX_ADDRESS_LEN: usize = 1023;
pub const MAX_SUPPORTED_VERSION: u8 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "sp",
            Self::Testnet => "tsp",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SilentPaymentAddress {
    pub network: Network,
    pub version: u8,
    pub scan_pubkey: AffinePoint,
    pub spend_pubkey: AffinePoint,
    pub extension_data: Vec<u8>,
}

fn polymod(hrp: &[u8], values: &[u8]) -> u32 {
    let mut chk = 1u32;
    let step = |chk: &mut u32, v: u8| {
        let top = *chk >> 25;
        *chk = ((*chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, gen) in GENERATORS.iter().enumerate() {
            if (top >> i) & 1 != 0 {
                *chk ^= *gen;
            }
        }
    };
    for &b in hrp {
        step(&mut chk, b >> 5);
    }
    step(&mut chk, 0);
    for &b in hrp {
        step(&mut chk, b & 31);
    }
    for &v in values {
        step(&mut chk, v);
    }
    chk
}

fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, Error> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let maxv = (1u32 << to_bits) - 1;
    let max_acc = (1u32 << (from_bits + to_bits - 1)) - 1;
    let mut out = Vec::with_capacity((data.len() * from_bits as usize).div_ceil(to_bits as usize));

    for &value in data {
        let v = u32::from(value);
        if (v >> from_bits) != 0 {
            return Err(Error::InvalidAddress);
        }
        acc = ((acc << from_bits) | v) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err(Error::InvalidAddress);
    }
    Ok(out)
}

fn decode_char(b: u8) -> Option<u8> {
    CHARSET.iter().position(|&c| c == b).map(|i| i as u8)
}

impl SilentPaymentAddress {
    pub fn new_v0(network: Network, scan_pubkey: AffinePoint, spend_pubkey: AffinePoint) -> Self {
        Self {
            network,
            version: 0,
            scan_pubkey,
            spend_pubkey,
            extension_data: Vec::new(),
        }
    }

    pub fn new(
        network: Network,
        version: u8,
        scan_pubkey: AffinePoint,
        spend_pubkey: AffinePoint,
        extension_data: Vec<u8>,
    ) -> Result<Self, Error> {
        if version > MAX_SUPPORTED_VERSION {
            return Err(Error::InvalidAddress);
        }
        if version == 0 && !extension_data.is_empty() {
            return Err(Error::InvalidAddress);
        }
        // Validate both points serialize to canonical compressed keys.
        let _ = compressed(&scan_pubkey)?;
        let _ = compressed(&spend_pubkey)?;
        Ok(Self {
            network,
            version,
            scan_pubkey,
            spend_pubkey,
            extension_data,
        })
    }

    pub fn encode(&self) -> Result<String, Error> {
        if self.version > MAX_SUPPORTED_VERSION {
            return Err(Error::InvalidAddress);
        }
        if self.version == 0 && !self.extension_data.is_empty() {
            return Err(Error::InvalidAddress);
        }
        let scan_bytes = compressed(&self.scan_pubkey)?;
        let spend_bytes = compressed(&self.spend_pubkey)?;
        let mut payload = Vec::with_capacity(66 + self.extension_data.len());
        payload.extend_from_slice(&scan_bytes);
        payload.extend_from_slice(&spend_bytes);
        payload.extend_from_slice(&self.extension_data);

        let converted = convert_bits(&payload, 8, 5, true)?;
        let mut data = Vec::with_capacity(1 + converted.len() + 6);
        data.push(self.version);
        data.extend_from_slice(&converted);

        let hrp = self.network.hrp();
        let mut chk_input = Vec::with_capacity(data.len() + 6);
        chk_input.extend_from_slice(&data);
        chk_input.extend_from_slice(&[0u8; 6]);
        let checksum = polymod(hrp.as_bytes(), &chk_input) ^ BECH32M_CONST;
        for i in 0..6 {
            data.push(((checksum >> (5 * (5 - i))) & 31) as u8);
        }

        let total_len = hrp.len() + 1 + data.len();
        if total_len > MAX_ADDRESS_LEN {
            return Err(Error::InvalidAddress);
        }
        let mut encoded = String::with_capacity(total_len);
        encoded.push_str(hrp);
        encoded.push('1');
        for v in data {
            encoded.push(char::from(CHARSET[usize::from(v)]));
        }
        Ok(encoded)
    }

    pub fn decode(address: &str) -> Result<Self, Error> {
        if address.is_empty() || address.len() > MAX_ADDRESS_LEN || !address.is_ascii() {
            return Err(Error::InvalidAddress);
        }
        let mut has_lower = false;
        let mut has_upper = false;
        for b in address.bytes() {
            if b.is_ascii_lowercase() {
                has_lower = true;
            } else if b.is_ascii_uppercase() {
                has_upper = true;
            } else if !(33..=126).contains(&b) {
                return Err(Error::InvalidAddress);
            }
        }
        if has_lower && has_upper {
            return Err(Error::InvalidAddress);
        }

        let lower = address.to_ascii_lowercase();
        let sep = lower.rfind('1').ok_or(Error::InvalidAddress)?;
        let hrp = &lower[..sep];
        let network = match hrp {
            "sp" => Network::Mainnet,
            "tsp" => Network::Testnet,
            _ => return Err(Error::InvalidAddress),
        };
        let data_part = &lower[sep + 1..];
        if data_part.len() < 7 {
            return Err(Error::InvalidAddress);
        }
        let mut data = Vec::with_capacity(data_part.len());
        for b in data_part.bytes() {
            data.push(decode_char(b).ok_or(Error::InvalidAddress)?);
        }
        if polymod(hrp.as_bytes(), &data) != BECH32M_CONST {
            return Err(Error::InvalidAddress);
        }
        let version = data[0];
        if version > MAX_SUPPORTED_VERSION {
            return Err(Error::InvalidAddress);
        }
        let payload = convert_bits(&data[1..data.len() - 6], 5, 8, false)?;
        if version == 0 {
            if payload.len() != 66 {
                return Err(Error::InvalidAddress);
            }
        } else if payload.len() < 66 {
            return Err(Error::InvalidAddress);
        }
        let scan_pubkey = point(&payload[..33])?;
        let spend_pubkey = point(&payload[33..66])?;
        let extension_data = payload[66..].to_vec();

        Ok(Self {
            network,
            version,
            scan_pubkey,
            spend_pubkey,
            extension_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, Scalar};

    #[test]
    fn bech32m_v0_and_v1_to_v30_forward_compatibility() {
        let scan = (ProjectivePoint::GENERATOR * Scalar::from(7u64)).to_affine();
        let spend = (ProjectivePoint::GENERATOR * Scalar::from(11u64)).to_affine();

        // v0 roundtrip (lowercase and uppercase).
        let v0 = SilentPaymentAddress::new_v0(Network::Mainnet, scan, spend);
        let encoded_v0 = v0.encode().unwrap();
        assert!(encoded_v0.starts_with("sp1q"));
        assert_eq!(SilentPaymentAddress::decode(&encoded_v0).unwrap(), v0);
        assert_eq!(
            SilentPaymentAddress::decode(&encoded_v0.to_ascii_uppercase()).unwrap(),
            v0
        );

        // Mixed case fails.
        let mut mixed = encoded_v0.clone();
        mixed.replace_range(0..1, "S");
        assert_eq!(
            SilentPaymentAddress::decode(&mixed),
            Err(Error::InvalidAddress)
        );

        // v1 preserves 32-byte extension_data verbatim.
        let ext = alloc::vec![0x2au8; 32];
        let v1 = SilentPaymentAddress::new(Network::Mainnet, 1, scan, spend, ext.clone()).unwrap();
        let encoded_v1 = v1.encode().unwrap();
        let decoded_v1 = SilentPaymentAddress::decode(&encoded_v1).unwrap();
        assert_eq!(decoded_v1.version, 1);
        assert_eq!(decoded_v1.scan_pubkey, scan);
        assert_eq!(decoded_v1.spend_pubkey, spend);
        assert_eq!(decoded_v1.extension_data, ext);

        // v30 succeeds and v31 fails.
        let v30 = SilentPaymentAddress::new(Network::Testnet, 30, scan, spend, Vec::new()).unwrap();
        let encoded_v30 = v30.encode().unwrap();
        assert_eq!(SilentPaymentAddress::decode(&encoded_v30).unwrap(), v30);
        assert_eq!(
            SilentPaymentAddress::new(Network::Mainnet, 31, scan, spend, Vec::new()),
            Err(Error::InvalidAddress)
        );

        // 1023-char cap: sp (2) + '1' (1) + ver (1) + 1013 data chars + 6 checksum = 1023.
        let max_ext = alloc::vec![0x55u8; 633 - 66];
        let max_sp =
            SilentPaymentAddress::new(Network::Mainnet, 1, scan, spend, max_ext.clone()).unwrap();
        let max_str = max_sp.encode().unwrap();
        assert_eq!(max_str.len(), MAX_ADDRESS_LEN);
        assert_eq!(SilentPaymentAddress::decode(&max_str).unwrap(), max_sp);

        // Same 633-byte payload under tsp hits 1024 chars and fails.
        let over_tsp =
            SilentPaymentAddress::new(Network::Testnet, 1, scan, spend, max_ext).unwrap();
        assert_eq!(over_tsp.encode(), Err(Error::InvalidAddress));
    }

    #[test]
    fn rejects_v0_trailing_bytes_and_bech32_const() {
        let scan = compressed(&AffinePoint::GENERATOR).unwrap();
        let spend = scan;
        // v0 with 67 bytes (1 trailing byte) fails.
        let mut payload = Vec::from(scan);
        payload.extend_from_slice(&spend);
        payload.push(0x42);
        let conv = convert_bits(&payload, 8, 5, true).unwrap();
        let mut data = alloc::vec![0u8];
        data.extend_from_slice(&conv);
        let mut chk_in = data.clone();
        chk_in.extend_from_slice(&[0u8; 6]);
        let chk = polymod(b"sp", &chk_in) ^ BECH32M_CONST;
        for i in 0..6 {
            data.push(((chk >> (5 * (5 - i))) & 31) as u8);
        }
        let mut s = String::from("sp1");
        for v in data {
            s.push(char::from(CHARSET[usize::from(v)]));
        }
        assert_eq!(SilentPaymentAddress::decode(&s), Err(Error::InvalidAddress));

        // v0 66 bytes with Bech32 const (1) instead of Bech32m fails.
        let mut payload66 = Vec::from(scan);
        payload66.extend_from_slice(&spend);
        let conv66 = convert_bits(&payload66, 8, 5, true).unwrap();
        let mut data66 = alloc::vec![0u8];
        data66.extend_from_slice(&conv66);
        let mut chk_in66 = data66.clone();
        chk_in66.extend_from_slice(&[0u8; 6]);
        let chk_bech32 = polymod(b"sp", &chk_in66) ^ 1;
        for i in 0..6 {
            data66.push(((chk_bech32 >> (5 * (5 - i))) & 31) as u8);
        }
        let mut s_bech32 = String::from("sp1");
        for v in data66 {
            s_bech32.push(char::from(CHARSET[usize::from(v)]));
        }
        assert_eq!(
            SilentPaymentAddress::decode(&s_bech32),
            Err(Error::InvalidAddress)
        );
    }
}
