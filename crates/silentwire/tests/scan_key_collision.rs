use silentwire::{
    compressed,
    input::PreparedTransaction,
    k256::{AffinePoint, ProjectivePoint},
    scalar,
    sender::{
        create_outputs, create_outputs_checked, ProvenancedRecipient, Recipient, RecipientOrigin,
        SenderInput,
    },
    tagged_hash, Error, SpScannerNaive,
};

struct Fixture {
    input: SenderInput,
    outpoint: [u8; 36],
    prepared: PreparedTransaction,
    scan_bytes: [u8; 32],
    scan_pub: AffinePoint,
    spend_pub: AffinePoint,
    spend_compressed: [u8; 33],
    change_m0_pub: AffinePoint,
    label_7_pub: AffinePoint,
    attacker_spend: AffinePoint,
    attacker_spend_2: AffinePoint,
}

fn label_spend(scan_bytes: &[u8; 32], spend_pub: AffinePoint, m: u32) -> AffinePoint {
    let tweak = scalar(tagged_hash(
        b"BIP0352/Label",
        &[scan_bytes.as_slice(), &m.to_be_bytes()],
    ))
    .unwrap();
    (ProjectivePoint::from(spend_pub) + ProjectivePoint::GENERATOR * tweak).to_affine()
}

fn fixture() -> Fixture {
    let mut a_in = [0u8; 32];
    a_in[31] = 0x11;
    let mut scan_bytes = [0u8; 32];
    scan_bytes[31] = 0x22;
    let mut spend_bytes = [0u8; 32];
    spend_bytes[31] = 0x33;
    let mut attacker_bytes = [0u8; 32];
    attacker_bytes[31] = 0x44;
    let mut attacker2_bytes = [0u8; 32];
    attacker2_bytes[31] = 0x55;

    let mut outpoint = [0u8; 36];
    outpoint[0] = 0xaa;

    let a_scalar = scalar(a_in).unwrap();
    let a_pub = (ProjectivePoint::GENERATOR * a_scalar).to_affine();
    let input_hash = scalar(tagged_hash(
        b"BIP0352/Inputs",
        &[&outpoint, &compressed(&a_pub).unwrap()],
    ))
    .unwrap();
    let prepared = PreparedTransaction {
        aggregate: a_pub,
        input_hash,
        tweak: ProjectivePoint::from(a_pub) * input_hash,
    };

    let scan_pub = (ProjectivePoint::GENERATOR * scalar(scan_bytes).unwrap()).to_affine();
    let spend_pub = (ProjectivePoint::GENERATOR * scalar(spend_bytes).unwrap()).to_affine();
    let spend_compressed = compressed(&spend_pub).unwrap();
    let change_m0_pub = label_spend(&scan_bytes, spend_pub, 0);
    let label_7_pub = label_spend(&scan_bytes, spend_pub, 7);
    let attacker_spend = (ProjectivePoint::GENERATOR * scalar(attacker_bytes).unwrap()).to_affine();
    let attacker_spend_2 =
        (ProjectivePoint::GENERATOR * scalar(attacker2_bytes).unwrap()).to_affine();

    Fixture {
        input: SenderInput {
            secret: a_in,
            is_taproot: false,
        },
        outpoint,
        prepared,
        scan_bytes,
        scan_pub,
        spend_pub,
        spend_compressed,
        change_m0_pub,
        label_7_pub,
        attacker_spend,
        attacker_spend_2,
    }
}

#[test]
fn unchecked_external_before_self_change_hides_change_on_rescan() {
    let f = fixture();
    // Mirrors senders that append own m = 0 change after external recipients.
    let outputs = create_outputs(
        &[f.input],
        &[f.outpoint],
        &[
            Recipient {
                scan: f.scan_pub,
                spend: f.attacker_spend,
            },
            Recipient {
                scan: f.scan_pub,
                spend: f.change_m0_pub,
            },
        ],
    )
    .unwrap();
    assert_eq!(outputs.len(), 2);

    // Exact cross-check against libsecp256k1 Case A output x-only pubkeys.
    let expected_attacker_k0: [u8; 32] =
        hex::decode("bfb496af7d2e981616458e3414cc1c028607c44a24e0b79c2785ba595e1a2b5f")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_change_k1: [u8; 32] =
        hex::decode("9abe568cfc0956758fe1c145f2544b61ff122ec913cda997333e9343d9197961")
            .unwrap()
            .try_into()
            .unwrap();
    assert!(outputs.contains(&expected_attacker_k0));
    assert!(outputs.contains(&expected_change_k1));

    let scanner = SpScannerNaive::new(f.scan_bytes, f.spend_compressed, &[0]).unwrap();
    let found = scanner.scan_prepared(&f.prepared, &outputs).unwrap();
    assert!(
        found.is_empty(),
        "attacker at k = 0 must hide m = 0 change at k = 1 under BIP-352 stop-at-first-miss"
    );
}

#[test]
fn checked_sender_recovers_self_change_obliviously_without_rejection() {
    let f = fixture();
    // External recipient supplied ahead of own change. Checked sender assigns
    // k = 0 to OwnVerified change and k = 1 to External without rejecting.
    let outputs = create_outputs_checked(
        &[f.input],
        &[f.outpoint],
        &[
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.attacker_spend,
                },
                origin: RecipientOrigin::External(1),
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.change_m0_pub,
                },
                origin: RecipientOrigin::OwnVerified,
            },
        ],
    )
    .unwrap();
    assert_eq!(outputs.len(), 2);

    // Positional mapping preserved: outputs[0] is attacker (k = 1), outputs[1] is change (k = 0).
    let expected_change_k0: [u8; 32] =
        hex::decode("632ee3d80477e17802831167e189b02d8c6817d549199ab860314cb2442aadeb")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_attacker_k1: [u8; 32] =
        hex::decode("5d8295db7e4ad4619b1e61f04c5c3aec9d376a43f40554c24c8ddae206fcc6d3")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(outputs[0], expected_attacker_k1);
    assert_eq!(outputs[1], expected_change_k0);

    let scanner = SpScannerNaive::new(f.scan_bytes, f.spend_compressed, &[0]).unwrap();
    // Verify scan recovery under both on-chain vout orders.
    for vouts in [[outputs[0], outputs[1]], [outputs[1], outputs[0]]] {
        let found = scanner.scan_prepared(&f.prepared, &vouts).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].derivation_index, 0);
        assert_eq!(found[0].label, Some(0));
        assert_eq!(found[0].taproot_pubkey, expected_change_k0);
    }
}

#[test]
fn checked_sender_orders_multiple_own_spend_keys_before_external() {
    let f = fixture();
    let outputs = create_outputs_checked(
        &[f.input],
        &[f.outpoint],
        &[
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.attacker_spend,
                },
                origin: RecipientOrigin::External(1),
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.change_m0_pub,
                },
                origin: RecipientOrigin::OwnVerified,
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.spend_pub,
                },
                origin: RecipientOrigin::OwnVerified,
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.label_7_pub,
                },
                origin: RecipientOrigin::OwnVerified,
            },
        ],
    )
    .unwrap();
    assert_eq!(outputs.len(), 4);

    let scanner = SpScannerNaive::new(f.scan_bytes, f.spend_compressed, &[0, 7]).unwrap();
    let found = scanner.scan_prepared(&f.prepared, &outputs).unwrap();
    assert_eq!(found.len(), 3);
    assert_eq!(found[0].derivation_index, 0);
    assert_eq!(found[0].label, Some(0));
    assert_eq!(found[0].taproot_pubkey, outputs[1]);
    assert_eq!(found[1].derivation_index, 1);
    assert_eq!(found[1].label, None);
    assert_eq!(found[1].taproot_pubkey, outputs[2]);
    assert_eq!(found[2].derivation_index, 2);
    assert_eq!(found[2].label, Some(7));
    assert_eq!(found[2].taproot_pubkey, outputs[3]);
}

#[test]
fn checked_sender_rejects_cross_party_collision_even_with_own_change() {
    let f = fixture();
    // Two distinct external parties with distinct spend keys sharing one scan key.
    let err = create_outputs_checked(
        &[f.input],
        &[f.outpoint],
        &[
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.attacker_spend,
                },
                origin: RecipientOrigin::External(1),
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.spend_pub,
                },
                origin: RecipientOrigin::External(2),
            },
        ],
    )
    .unwrap_err();
    assert_eq!(err, Error::ScanKeyCollision);

    // Must still reject when OwnVerified is present to avoid a two-account oracle.
    let err_with_own = create_outputs_checked(
        &[f.input],
        &[f.outpoint],
        &[
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.change_m0_pub,
                },
                origin: RecipientOrigin::OwnVerified,
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.attacker_spend,
                },
                origin: RecipientOrigin::External(1),
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.attacker_spend_2,
                },
                origin: RecipientOrigin::External(2),
            },
        ],
    )
    .unwrap_err();
    assert_eq!(err_with_own, Error::ScanKeyCollision);
}

#[test]
fn checked_sender_allows_same_party_labels_and_identical_cross_party_addresses() {
    let f = fixture();
    let scanner = SpScannerNaive::new(f.scan_bytes, f.spend_compressed, &[0, 7]).unwrap();

    // Same external party supplying multiple labeled spend keys.
    let same_party = create_outputs_checked(
        &[f.input],
        &[f.outpoint],
        &[
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.spend_pub,
                },
                origin: RecipientOrigin::External(42),
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.label_7_pub,
                },
                origin: RecipientOrigin::External(42),
            },
        ],
    )
    .unwrap();
    let found_same = scanner.scan_prepared(&f.prepared, &same_party).unwrap();
    assert_eq!(found_same.len(), 2);

    // Two distinct external parties paying the exact same (scan, spend) address.
    let identical = create_outputs_checked(
        &[f.input],
        &[f.outpoint],
        &[
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.spend_pub,
                },
                origin: RecipientOrigin::External(1),
            },
            ProvenancedRecipient {
                recipient: Recipient {
                    scan: f.scan_pub,
                    spend: f.spend_pub,
                },
                origin: RecipientOrigin::External(2),
            },
        ],
    )
    .unwrap();
    let found_ident = scanner.scan_prepared(&f.prepared, &identical).unwrap();
    assert_eq!(found_ident.len(), 2);
}

#[test]
fn four_group_ordering_cases_match_bip352_stop_at_first_miss() {
    let f = fixture();
    let scanner = SpScannerNaive::new(f.scan_bytes, f.spend_compressed, &[0, 7]).unwrap();
    let genuine = Recipient {
        scan: f.scan_pub,
        spend: f.spend_pub,
    };
    let genuine_m0 = Recipient {
        scan: f.scan_pub,
        spend: f.change_m0_pub,
    };
    let genuine_m7 = Recipient {
        scan: f.scan_pub,
        spend: f.label_7_pub,
    };
    let fake = Recipient {
        scan: f.scan_pub,
        spend: f.attacker_spend,
    };
    let fake2 = Recipient {
        scan: f.scan_pub,
        spend: f.attacker_spend_2,
    };

    // Genuine k=0, fake k=1 -> 1 match.
    let out1 = create_outputs(&[f.input], &[f.outpoint], &[genuine, fake]).unwrap();
    assert_eq!(scanner.scan_prepared(&f.prepared, &out1).unwrap().len(), 1);

    // Fake k=0, genuine k=1 -> 0 matches.
    let out2 = create_outputs(&[f.input], &[f.outpoint], &[fake, genuine]).unwrap();
    assert_eq!(scanner.scan_prepared(&f.prepared, &out2).unwrap().len(), 0);

    // Three genuine k=0..2 and two fakes k=3..4 in reversed output order -> 3 matches.
    let mut out3 = create_outputs(
        &[f.input],
        &[f.outpoint],
        &[genuine, genuine_m0, genuine_m7, fake, fake2],
    )
    .unwrap();
    out3.reverse();
    assert_eq!(scanner.scan_prepared(&f.prepared, &out3).unwrap().len(), 3);

    // Genuine k=0, fake k=1, genuine k=2 -> stops at missing k=1 (1 match).
    let out4 = create_outputs(&[f.input], &[f.outpoint], &[genuine, fake, genuine_m7]).unwrap();
    let found4 = scanner.scan_prepared(&f.prepared, &out4).unwrap();
    assert_eq!(found4.len(), 1);
    assert_eq!(found4[0].derivation_index, 0);
}
