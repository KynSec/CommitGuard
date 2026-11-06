# Package manager manifests

These manifests are release inputs. They are not published packages by
themselves.

1. Build and verify the signed release artifacts.
2. Run `python scripts/validate_packaging.py --version <version>` after updating
   the URLs and hashes.
3. Submit the Homebrew formula or Scoop manifest to its upstream repository and
   record the result in the release notes.

Homebrew uses the PyPI source archive plus a `pyyaml` resource. Scoop installs
the same source archive with Python and exposes the `commit-guard` launcher.
Keep the manifest version equal to `core.__version__`.
