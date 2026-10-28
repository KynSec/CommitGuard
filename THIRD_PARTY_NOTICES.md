# Third-party notices

CommitGuard is distributed under the Apache License 2.0. This file records
third-party components and bundled data that have separate attribution or
license terms.

The machine-readable source of truth for bundled rule packs is
[`rules/PROVENANCE.yaml`](rules/PROVENANCE.yaml). A component marked
`release-blocked` must not be included in a published artifact until its license
has been reviewed and the entry is marked `cleared`.

## Runtime dependency

### PyYAML

- Project: https://pyyaml.org/
- Version range: `PyYAML>=6.0`
- License: MIT
- Use: parsing YAML rule packs and rule corpus files

## Bundled rule data

### gitleaks default configuration

- Project: https://github.com/gitleaks/gitleaks
- Source: `config/gitleaks.toml` at tag `v8.30.1`
- File: `rules/gitleaks.toml`
- License: MIT
- Use: secret-detection patterns
- Local change: one allowlist regex was regrouped so Python's `re` applies the
  case-insensitive flag to the whole alternation. The change is recorded in
  `rules/PROVENANCE.yaml`.

### Microsoft DevSkim default rules

- Project: https://github.com/microsoft/DevSkim
- Source: `rules/default` at commit
  `bd81f6967d84b3ef1dbce9e466dc28e124f56289`
- Files: `rules/general/devskim/*.yaml`
- License: MIT; the upstream license text is bundled at
  `rules/general/devskim/LICENSE.txt`
- Use: broad language and framework security checks
- Conversion: `scripts/fetch_general_rules.py` converts only the regex-compatible
  subset. Rules requiring DevSkim's structured analyzers are omitted rather than
  approximated.

### Semgrep rules

- Project: https://github.com/semgrep/semgrep-rules
- Files: `rules/semgrep_rules/*.yaml`
- License: Semgrep Rules License v1.0
- License text: https://semgrep.dev/legal/rules-license
- Status: **release-blocked — redistribution is not permitted by the license**
- Use: local development reference and regex-compatible subset of the Semgrep
  rule corpus

The Semgrep Rules License permits internal use only and does not allow the rules
to be distributed or made available to others. These files are therefore
excluded from built wheels and source distributions and must not be uploaded to
PyPI or any other release channel. Some upstream rule metadata may also carry
per-rule licenses, including Commons Clause/LGPL references; those terms require
file-by-file review before any future redistribution.

### OWASP Core Rule Set SQL-injection pack

- Project: https://github.com/coreruleset/coreruleset
- Source: `rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf` at commit
  `87de6a8e04c774533e6e939323588a61cca46a6a` (version `4.30.0-dev`)
- File: `rules/experimental/owasp_sqli.conf`
- License: Apache License 2.0
- Status: reference-only; not loaded or executed by default

### Bandit B102 plugin

- Project: https://github.com/PyCQA/bandit
- Source: `bandit/plugins/exec.py` at commit
  `3aaa2b07be47090344d89e5532bcde15127c2909`
- File: `rules/experimental/bandit_exec_rule.py`
- License: Apache License 2.0
- Status: reference-only; not executed by CommitGuard

## Project-authored rule packs

The following packs are original project work under Apache-2.0:

- `rules/custom_rules.yaml`
- `rules/ai_security/rules.yaml`
- `rules/iac/rules.yaml`
- `rules/general/web.yaml`
- `rules/general/authz.yaml`
- `rules/general/deserialization.yaml`
- `rules/general/supply_chain.yaml`
- `rules/corpus.yaml`
- `rules/nuclei_generic_key.yaml`

## Future engines and adapters

No third-party scanning engine is bundled today. If Semgrep, Opengrep, Trivy,
Checkov, gitleaks, or another external engine is added, its license, version,
invocation contract, and distribution terms must be recorded here and in
`rules/PROVENANCE.yaml` before release.

## MIT license text

The MIT-licensed components above are used under the following terms:

```text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Apache License 2.0

Apache-2.0 components are used under the terms in [`LICENSE`](LICENSE). The
license is also available at https://www.apache.org/licenses/LICENSE-2.0.
