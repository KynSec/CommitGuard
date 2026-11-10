# Releasing CommitGuard

Release artifacts are built by
`.github/workflows/release.yml` on a `v*` tag. The workflow fails when the tag
does not match `core.__version__`.

## Artifacts

| Artifact | Purpose |
|---|---|
| `commit_guard-<version>-py3-none-any.whl` | pip / pipx install. |
| `commit_guard-<version>.tar.gz` | Source distribution. |
| `commit-guard.pyz` | Single-file Python zipapp with bundled native rules. |
| `commit-guard.cdx.json` | CycloneDX SBOM for CommitGuard. |
| `commit-guard.spdx.json` | SPDX SBOM for CommitGuard. |
| `SHA256SUMS` | Checksums for every artifact. |
| `SHA256SUMS.sig` | Detached OpenSSL signature for `SHA256SUMS`. |
| `SHA256SUMS.pub` | Public key used to verify `SHA256SUMS.sig`. |
| `commitguard-kynsec-<version>.vsix` | VS Code extension package for the Marketplace or `code --install-extension`. |
| `ghcr.io/kynsec/commitguard:<tag>` | Container image. |

Build provenance is attested with `actions/attest-build-provenance`. Semgrep
rule packs are excluded from wheels, sdists, zipapps, and the container image
because their upstream license forbids redistribution.

## Verifying a release

`SHA256SUMS` is signed with the release signing key. The matching public key is
published as `SHA256SUMS.pub` and committed at
`docs/RELEASE-SIGNING-KEY.pub` (SHA-256 fingerprint
`fa04a699861b4918c0386e99eda600398360041e61b32848ae97e3dd187d73ed`):

```bash
openssl dgst -sha256 -verify SHA256SUMS.pub \
  -signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
```

The private key is stored only in the `RELEASE_SIGNING_KEY_B64` repository
secret. Rotate the key by publishing the new public key with the next release.

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
`dashboard`, `watch`, `lsp`, `compliance`, `audit`, `plugin`, and `gate`.
Installing hooks or refreshing a repository toolkit still requires the wheel or
installer.

## Package manager distribution

Homebrew and Scoop manifests live under `packaging/` and are updated only after
the signed release artifacts exist:

```bash
python scripts/validate_packaging.py --version 3.4.0 \
  --artifact dist/commit_guard-3.4.0.tar.gz
```

Update the formula and manifest URL, version, and SHA-256, then submit them to
the respective upstream repositories. The release workflow publishes the
container image with both the release tag and `latest`:

```bash
docker pull ghcr.io/kynsec/commitguard:v3.4.0
docker run --rm -v "$PWD:/workspace" ghcr.io/kynsec/commitguard:v3.4.0 \
  scan --staged
```

The GHCR package must be public for anonymous pulls. If it is private,
authenticate with `docker login ghcr.io` or change the package visibility in
the organization package settings.

Do not treat an in-repo manifest as a published package. Record the upstream
submission or merge in the release notes.

## Offline OSV snapshots

Signed snapshots use an HMAC-SHA256 sidecar and never send data to the network:

```bash
export COMMITGUARD_OSV_SIGNING_KEY=...
python scripts/sign_osv_snapshot.py .commit_guard_osv.json
commit-guard scan --sca --sca-require-signature
```

A present sidecar is always verified. `--sca-require-signature` additionally
rejects unsigned snapshots so CI can enforce integrity.

## Native binaries

The optional `Native binaries` workflow builds PyInstaller artifacts for Linux,
macOS, and Windows on a `v*` tag or manual dispatch. These are convenience
downloads for users without Python; the wheel, sdist, zipapp, SBOMs, and
checksums remain the canonical signed release artifacts.

```bash
python -m pip install pyinstaller
python scripts/build_native.py --output-dir dist/native
```

The workflow smoke-tests `--version` on each platform. Do not publish a native
artifact without also publishing the matching signed Python artifacts and
checksums.
