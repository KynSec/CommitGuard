class Commitguard < Formula
  include Language::Python::Virtualenv

  desc "Offline-first local security control plane for secrets, SAST, SCA, and policy"
  homepage "https://github.com/CommitGuard-Sec/CommitGuard"
  url "https://files.pythonhosted.org/packages/source/c/commit-guard/commit-guard-3.0.0.tar.gz"
  sha256 "REPLACE_WITH_RELEASE_SHA256"
  license "Apache-2.0"

  depends_on "python@3.12"
  depends_on "git"

  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/source/p/pyyaml/PyYAML-6.0.2.tar.gz"
    sha256 "REPLACE_WITH_PYYAML_SHA256"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "Commit Guard", shell_output("#{bin}/commit-guard --version")
  end
end
