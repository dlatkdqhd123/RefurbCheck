#!/usr/bin/env python3
"""Regenerate a harmless public-certificate fixture; private keys stay in memory.

Requires Python cryptography only to regenerate, not to run the Java tests.
The fixture deliberately imitates Google subject names with a different key.
It is NOT a usable Google attestation and must never become a trust anchor in
the Android app. Random test keys make regeneration bytewise nondeterministic.
"""
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier


def date(year):
    return datetime(year, 1, 1, tzinfo=timezone.utc)


def certificate(subject, issuer, public_key, signing_key, serial, start, end, ca,
                attested=False):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(public_key).serial_number(serial)
               .not_valid_before(date(start)).not_valid_after(date(end))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if attested:
        # Presence-only marker: chain verification is tested before schema parsing.
        builder = builder.add_extension(x509.UnrecognizedExtension(
            ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), b"\x30\x00"), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(4)]
names = [
    x509.Name([x509.NameAttribute(NameOID.SERIAL_NUMBER, "f92009e853b6b045")]),
    x509.Name([x509.NameAttribute(NameOID.SERIAL_NUMBER, "e18c4f2ca699739a"),
               x509.NameAttribute(NameOID.TITLE, "TEE")]),
    x509.Name([x509.NameAttribute(NameOID.SERIAL_NUMBER, "lookalike-test-only")]),
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test-only leaf")]),
]
root = certificate(names[0], names[0], keys[0].public_key(), keys[0], 101, 2000, 2040, True)
intermediate = certificate(names[1], names[0], keys[1].public_key(), keys[0], 102, 2010, 2020, True)
attestation = certificate(names[2], names[1], keys[2].public_key(), keys[1], 103, 2010, 2020, True)
leaf = certificate(names[3], names[2], keys[3].public_key(), keys[2], 104, 1970, 2048, False, True)
Path(__file__).with_name("factory-lookalike-chain.pem").write_bytes(b"".join(
    cert.public_bytes(serialization.Encoding.PEM) for cert in [leaf, attestation, intermediate, root]))
