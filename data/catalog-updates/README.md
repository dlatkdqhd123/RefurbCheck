# Signed reference-catalog distribution

`catalog-update.zip` is a data-only bundle consumed by RefurbCheck 1.3+. The
separately pinned RSA update public key is in `app/src/main/assets/catalog_update_key.der`.
No private key, executable rules, APKs or malware samples are included.

The first bundle wraps the reviewed **2026-11-06** snapshot (15,645 references;
996 ClamAV-only exclusions) without changing its source retrieval timestamp.
It does not add 15,645 newly discovered malware samples. Source metadata and
attribution are inside `malware_catalog.json`; source-specific original licenses,
selected data and conversion sources remain under `data/antivirus/` and the APK's
`antivirus_licenses/` assets. Data licenses remain GPL-2.0-only / BSD-2-Clause /
CC-BY-4.0 / MIT as identified per source; they are not relicensed as app code.

See [catalog-updates.md](../../docs/catalog-updates.md) for format, freshness,
rollback limits, publication procedure and test scope. The ZIP at this source
path is reproducible using the offline signing key and exact recorded timestamp.
The app's fixed download address uses a separate `catalog-updates` branch root;
changing only this source directory does not publish a live data update.
