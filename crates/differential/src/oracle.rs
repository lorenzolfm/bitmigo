// SPDX-License-Identifier: MIT OR Apache-2.0

//! The oracle: Bitcoin Core 26.0's `VerifyScript`, reached through `libbitcoinconsensus`.
//!
//! The library answers one question, "does input `index` of this serialized transaction
//! spend `script_pubkey` under `flags`", and that is the only question asked of it. Its
//! other error codes (bad flags, wrong prevout count, undecodable transaction) describe a
//! misuse of the library by this harness, never a script verdict, so they are assertions
//! here: a fuzzer that silently counted them as "invalid" would report agreement on cases
//! it never compared.

use bitcoin::TxOut;
use bitcoinconsensus::{Error, Utxo};
use bitmigo_consensus::script::ScriptFlags;

/// Core's verdict on input `index` of `tx_bytes`, which spends `prevouts[index]`, under
/// `flags`. Always the `_with_spent_outputs` entry point, so that every prevout is available
/// for the BIP341 digest whether or not `TAPROOT` is set; Core only reads them when it is.
#[must_use]
pub fn verify(tx_bytes: &[u8], index: usize, prevouts: &[TxOut], flags: ScriptFlags) -> bool {
    assert!(index < prevouts.len());
    assert!(flags.is_subset_of(ScriptFlags::MANDATORY));
    let spent = prevouts.get(index).expect("index < prevouts.len()");
    let utxos: Vec<Utxo> = prevouts.iter().map(utxo).collect();
    assert_eq!(utxos.len(), prevouts.len());
    let verdict = bitcoinconsensus::verify_with_flags(
        spent.script_pubkey.as_bytes(),
        spent.value.to_sat(),
        tx_bytes,
        Some(&utxos),
        index,
        flags.bits(),
    );
    match verdict {
        Ok(()) => true,
        // `ERR_SCRIPT` is the binding's name for Core's `ERR_OK` with a false return: the
        // transaction decoded, the flags were legal, and the script failed.
        Err(Error::ERR_SCRIPT) => false,
        Err(other) => panic!("the oracle refused the harness's input: {other}"),
    }
}

/// Core's `UTXO` view of a `TxOut`: a pointer into the output's script and its value.
/// Building one is safe Rust; only the library dereferences it, and only for the duration of
/// the call the caller holds `prevouts` across.
fn utxo(output: &TxOut) -> Utxo {
    let script = output.script_pubkey.as_bytes();
    Utxo {
        script_pubkey: script.as_ptr(),
        script_pubkey_len: u32::try_from(script.len()).expect("a script fits in u32"),
        value: i64::try_from(output.value.to_sat()).expect("an amount fits in i64"),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::deserialize;
    use bitcoin::hex::FromHex;
    use bitcoin::{Amount, ScriptBuf, TxOut};
    use bitmigo_consensus::script::ScriptFlags;

    use super::verify;

    /// The P2SH-P2WPKH spend from the binding's own test suite: the library is linked, the
    /// amount reaches the BIP143 digest (a wrong amount flips the verdict), and `ERR_SCRIPT`
    /// is a verdict rather than a panic.
    #[test]
    fn library_is_linked_and_answers() {
        // `BITCOINCONSENSUS_API_VER` at Core 26.0: 2 since the spent-outputs entry point.
        assert_eq!(bitcoinconsensus::version(), 2);
        let spk = Vec::<u8>::from_hex("a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87").unwrap();
        let tx = Vec::<u8>::from_hex(
            "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df\
             0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c0000000000\
             17a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58ae\
             dd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2\
             d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe\
             16aad536293d15e300000000",
        )
        .unwrap();
        let prevout = |sat| TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        };
        assert!(verify(
            &tx,
            0,
            &[prevout(1_900_000)],
            ScriptFlags::MANDATORY
        ));
        assert!(!verify(&tx, 0, &[prevout(900_000)], ScriptFlags::MANDATORY));
        // Without WITNESS the program is anyone-can-spend and the amount is not hashed.
        assert!(verify(&tx, 0, &[prevout(900_000)], ScriptFlags::P2SH));
    }

    #[test]
    #[should_panic(expected = "refused the harness's input")]
    fn undecodable_transaction_is_a_harness_bug() {
        let prevout = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        };
        assert!(!verify(&[0xff; 3], 0, &[prevout], ScriptFlags::NONE));
    }

    #[test]
    fn deserialize_round_trips_a_prevout() {
        let bytes = Vec::<u8>::from_hex("01000000000000000151").unwrap();
        let out: TxOut = deserialize(&bytes).unwrap();
        assert_eq!(out.value.to_sat(), 1);
        assert_eq!(out.script_pubkey.as_bytes(), &[0x51]);
    }
}
