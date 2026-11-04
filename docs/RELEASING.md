# Releasing CommitGuard

Phase 2 release artifacts are built by
`.github/workflows/release.yml` on a `v*` tag. The workflow fails when the tag
does not match `core.__version__`.

## Artifacts

| Artifact | Purpose |
|---|---|
| `commit_guard-<version>-py3-none-any.whl` | pip / pipx install. |
| `commit-guard-<version>.tar.gz` | Source distribution. |
| `commit-guard.pyz` | Single-file Python zipapp with bundled native rules. |
| `commit-guard.cdx.json` | CycloneDX SBOM for CommitGuard. |
| `commit-guard.spdx.json` | SPDX SBOM for CommitGuard. |
| `SHA256SUMS` | Checksums for every artifact. |
| `SHA256SUMS.sig` | Detached OpenSSL signature when the signing key is set. |
| `commitguard-kynsec-<version>.vsix` | VS Code extension package for the Marketplace or `code --install-extension`. |
| `ghcr.io/commitguard-sec/commitguard:<tag>` | Container image. |

Build provenance is attested with `actions/attest-build-provenance`. Semgrep
rule packs are excluded from wheels, sdists, zipapps, and the container image
because their upstream license forbids redistribution.

## VS Code extension

The release workflow compiles, tests, and packages `editors/vscode/`, then
copies the VSIX into `dist/`. Marketplace publishing is a manual step after the
artifacts pass review:

```bash
cd editors/vscode
npm ci
npm run compile
npm test
npm run package
npx vsce publish
```

The published listing is [CommitGuard Security Scanner (KynSec)](https://marketplace.visualstudio.com/items?itemName=AmrKhaledEldhshan.commitguard-kynsec).
Verify the Marketplace version matches the source tag before announcing a
release.

## Signing

Add a PEM private key as the `RELEASE_SIGNING_KEY_B64` repository secret
(base64-encoded). The workflow signs `SHA256SUMS` with:

```bash
openssl dgst -sha256 -sign release-signing-key.pem \
  -out SHA256SUMS.sig SHA256SUMS
```

Store the matching public key in the repository or release notes so users can
verify offline.

## Offline verification

```bash
python scripts/verify_release.py dist --public-key release-public.pem \
  --require-signature
```

For operators without the verification script:

```bash
sha256sum --check SHA256SUMS
openssl dgst -sha256 -verify release-public.pem \
  -signature SHA256SUMS.sig SHA256SUMS
```

## Zipapp notes

The zipapp extracts the bundled native rules into
`$COMMITGUARD_CACHE_DIR` (default `~/.cache/commitguard`) on first run. It
supports scan and read-only command surfaces such as `sbom`, `license`,
`dashboard`, `watch`, `lsp`, `compliance`, `plugin`, and `gate`. Installing
hooks or refreshing a repository toolkit still requires the wheel or installer.

## Offline OSV snapshots

Signed snapshots use an HMAC-SHA256 sidecar and never send data to the network:

```bash
export COMMITGUARD_OSV_SIGNING_KEY=...
python scripts/sign_osv_snapshot.py .commit_guard_osv.json
commit-guard scan --sca --sca-require-signature
```

A present sidecar is always verified. `--sca-require-signature` additionally
rejects unsigned snapshots so CI can enforce integrity.
