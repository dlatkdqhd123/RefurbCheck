# Attestation v1.3 public fixtures

These files contain public certificates only, never private attestation keys.
They test chain/date-policy decisions and do not establish trust in the phone
running RefurbCheck or measure malware detection accuracy.

## Official Android verifier fixtures

Source: [android/keyattestation v0.4](https://github.com/android/keyattestation/tree/v0.4)
at commit `621149c4ebaeeea844d6f43098687c73c4d370a3`, Apache License 2.0.
The complete license is copied to `GOOGLE_TESTDATA_LICENSE`.

| Local file | Unmodified upstream path | SHA-256 |
| --- | --- | --- |
| `google-v04-factory-blueline.pem` | `testdata/blueline/sdk28/TEE_EC_NONE.pem` | `3f37e6a91eaa0fc581bfa16e853407fb2d810a9b03ce84884726737a6e899a3f` |
| `google-v04-rkp-caiman.pem` | `testdata/caiman/sdk36/TEE_EC_RKP.pem` | `6194cd75cea7bb635d898be13cb72880771f7192f90fa9507279c95c86a395ec` |

The upstream `KeyAttestationCertPathValidatorTest` uses these files to require
that the factory path remains accepted at 2030-01-01 but the expired RKP path
does not. RefurbCheck checks those two reference outcomes with its own stricter
PKIX-based verifier. This is a targeted compatibility regression, not a claim
of full equivalence or execution of the complete official Kotlin test suite.

The factory fixture also includes an expired, older Google root certificate.
The app must link its subject/public key to the current pinned Google root,
rather than trusting a certificate solely because its subject looks familiar.

## Synthetic lookalike authority

`factory-lookalike-chain.pem` uses synthetic EC P-256 keys and public names that
imitate the legacy authority and factory intermediate. Its CA certificates are
expired at the test time. Even if a host test supplies its own root as a trust
anchor, the Google-only expiry exception must remain disabled because the
public key is different. This fixture is never packaged as an app trust root.

Regenerate with `python3 tests/attestation-fixtures/generate_factory_lookalike.py`
if needed. The generator uses Python `cryptography`, creates random test keys
in memory, writes only public certificates, and discards all private keys.
Regeneration changes certificate bytes but preserves the negative test case.
