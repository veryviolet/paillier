"""The package's licensing state — checkable rather than promised.

The occasion was concrete. The wheel declared `MIT OR Apache-2.0` while
GMP is linked into the extension STATICALLY through `rug`, and `rug` and
`gmp-mpfr-sys` are LGPL-3.0+. So the distributed binary is a combined
work under LGPL §4, and the metadata said nothing about it.

It would have gone on saying nothing: nothing in the build ties the set
of dependencies to what `pyproject.toml` claims. Swapping `rug` for
another backend, or adding one more LGPL/GPL dependency, would pass
unnoticed until the first complaint.

So what is checked is not the text but the correspondence: which
licences are actually in the dependency tree, and what is said about
them.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Crates whose licence is stronger than permissive and which therefore
# have to be named. Read from `Cargo.lock`, not from memory.
COPYLEFT = {"rug", "gmp-mpfr-sys"}

REQUIRED_FILES = [
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "LICENSE-LGPL",
    "LICENSE-GPL",
    "NOTICE.md",
]


def cargo_lock_crates():
    text = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
    return set(re.findall(r'^name = "([^"]+)"', text, re.MULTILINE))


def pyproject():
    return (ROOT / "pyproject.toml").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", REQUIRED_FILES)
def test_licence_file_is_present(name):
    path = ROOT / name
    assert path.exists(), f"{name} is promised in pyproject but absent"
    assert path.stat().st_size > 500, f"{name} is suspiciously short"


@pytest.mark.parametrize("name", REQUIRED_FILES)
def test_licence_file_is_declared_in_pyproject(name):
    assert f'"{name}"' in pyproject(), (
        f"{name} sits in the repository but is not named in license-files "
        f"— so it will not make it into the wheel"
    )


def test_copyleft_dependencies_are_reflected_in_the_expression():
    """LGPL in the tree obliges us to say so in the metadata.

    This is the check that catches the original defect: `rug` is in
    `Cargo.lock`, GMP is linked statically, and the expression promised
    permissive licences only.
    """
    present = COPYLEFT & cargo_lock_crates()
    assert present, (
        "neither rug nor gmp-mpfr-sys is in Cargo.lock — if the bignum "
        "backend changed, this check must be rewritten, not deleted"
    )

    declared = re.search(r'^license = "([^"]+)"', pyproject(), re.MULTILINE)
    assert declared, "no licence expression in pyproject"

    assert "LGPL-3.0-or-later" in declared.group(1), (
        f"the dependencies include {sorted(present)} under LGPL-3.0+ while "
        f"the wheel declares {declared.group(1)}: GMP is linked into the "
        f"extension statically, so this is a combined work"
    )


def test_notice_names_every_copyleft_dependency():
    notice = (ROOT / "NOTICE.md").read_text(encoding="utf-8")
    for name in sorted(COPYLEFT & cargo_lock_crates()):
        assert name in notice, f"{name} is not named in NOTICE.md"


def test_the_notice_is_visible_to_a_reader():
    """LGPL §4(a) demands a PROMINENT notice, not a file in a corner."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "NOTICE.md" in readme or "LGPL" in readme, (
        "README mentions neither NOTICE.md nor LGPL — a notice nobody "
        "sees is not a notice"
    )


def test_fast_paillier_stays_in_dev_dependencies():
    """It is a test oracle and must not be part of the library build.

    Moving it into ordinary dependencies would change both the wheel's
    contents and the licensing picture — silently.
    """
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    dev = manifest.index("[dev-dependencies]")

    assert "fast-paillier" not in manifest[:dev], (
        "fast-paillier ended up in ordinary dependencies: it is a test "
        "oracle, not part of the library"
    )
    assert "fast-paillier" in manifest[dev:]


def test_the_built_extension_contains_no_oracle_code():
    """Checked against the BINARY, not against the manifest.

    A manifest states an intention; the binary states what shipped.
    """
    import paillier

    # The module file itself, not the first `.so` in the directory. The
    # module installs both as a package (`paillier/paillier.*.so`) and as
    # a bare extension (`site-packages/paillier.so`), and in the second
    # case `parent` is the whole of `site-packages`: the first `glob`
    # iteration would pick up some other library and declare our binary
    # dirty. That is how this test failed the first time.
    module = Path(paillier.__file__)
    if module.suffix in {".so", ".pyd"}:
        binary = module
    else:
        found = sorted(module.parent.glob("paillier*.so")) or sorted(
            module.parent.glob("paillier*.pyd")
        )
        if not found:
            pytest.skip("the module is not built as an extension here")
        binary = found[0]

    blob = binary.read_bytes()
    assert b"fast_paillier" not in blob and b"fast-paillier" not in blob, (
        "oracle code ended up in the built extension"
    )
    # GMP, on the other hand, DID end up there — which is exactly what
    # NOTICE.md exists for.
    assert b"GNU MP" in blob, (
        "GMP was not found in the binary: if the linkage became dynamic, "
        "the licensing position changed and NOTICE.md must be rewritten"
    )


@pytest.mark.parametrize("crate", sorted(COPYLEFT))
def test_the_copyleft_dependencies_are_not_pinned_exactly(crate):
    """LGPL §4(d)(0): a user must be able to relink against a DIFFERENT
    version of the library.

    An exact pin (`=1.30.0`) gets in the way: rebuilding against your own
    GMP would require editing our manifest.

    Over BOTH copyleft crates, not just `rug`. This checked `rug` alone
    while `gmp-mpfr-sys` was merely transitive; it is now a DIRECT
    dependency — and it is the crate that actually carries GMP — so
    pinning it exactly would obstruct relinking just as much, with
    nothing to notice.

    A crate in `COPYLEFT` with no direct dependency line at all is
    skipped rather than failed: being transitive is not a defect, and
    demanding a line here would push us to declare dependencies we do not
    use.

    But a line that EXISTS and cannot be parsed is a failure, not a skip.
    Matching only `name = "…"` let the table form through:
    `gmp-mpfr-sys = { version = "=1.7.1" }` stopped matching, the row
    skipped, and the summary read `18 passed, 1 skipped` — the exact
    vacuity the test below is named after, one level down.
    """
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    line = re.search(rf"^{re.escape(crate)} = (.+)$", manifest, re.MULTILINE)
    if not line:
        pytest.skip(f"{crate} is not a direct dependency")

    # Both forms: `name = "1.7"` and `name = { version = "1.7", … }`.
    declared = line.group(1)
    version = re.search(r'version\s*=\s*"([^"]+)"', declared) or re.match(
        r'"([^"]+)"', declared
    )

    assert version, (
        f"{crate} has a dependency line that no version could be read from: "
        f"{declared}. Skipping here would hide an exact pin behind a syntax "
        f"the parser does not know"
    )
    assert not version.group(1).startswith("="), (
        f"{crate} is pinned as {version.group(1)}: an exact pin obstructs the "
        f"relinking LGPL §4(d) requires"
    )


def test_at_least_one_copyleft_crate_is_direct():
    """Otherwise the parametrised test above skips everything and passes.

    An assertion of absence goes green on emptiness, and a row of skips
    reads exactly like a row of passes in the summary line.
    """
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    direct = [
        crate
        for crate in COPYLEFT
        if re.search(rf"^{re.escape(crate)} = ", manifest, re.MULTILINE)
    ]

    assert direct, (
        f"none of {sorted(COPYLEFT)} is a direct dependency, so the pin "
        f"check above tested nothing"
    )


def test_the_notice_is_tracked_by_git():
    """A notice outside the index reaches neither the tag nor the
    wheel."""
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "NOTICE.md"],
        capture_output=True,
    )
    assert tracked.returncode == 0, "NOTICE.md is not in the git index"
