"""Everything the documentation points at exists AND is under git.

This check appeared after two breakages in one document:
`benches/timing_by_weight.rs` was described as a benchmark "kept in the
repository" long after it had moved to `tests/timing_channel.rs`; and the
accuracy measurements were referred to by paths inside a temporary
directory that never reaches the reader at all.

Two checks rather than one, and the second matters more. A file can sit
on my disk and be absent from the index — then it reaches neither the tag
nor a clone, and the link breaks for exactly the person who came to read.
A release has already gone out missing two files that way.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# A reference to a repository file in two forms at once: a path in
# backticks, and the target of a markdown link `[text](path)`. The second
# form is not there for completeness: the README links to documents
# exactly that way, and with only the first form it was checked FOR
# NOTHING — it contained no backticked paths at all, so a broken link
# there would have gone unseen.
#
# A build file (`Cargo.toml`) is deliberately excluded: the subject of the
# check is documentation naming SECTIONS of the repository that do not
# exist.
REFERENCE = re.compile(
    r"`((?:src|tests|benches|docs)/[A-Za-z0-9_./-]+)`"
    r"|\]\(((?:src|tests|benches|docs)/[A-Za-z0-9_./-]+)\)"
)


def documents():
    # rglob, not glob: the site pages live in subdirectories
    # (`docs/concepts/`, `docs/reference/`), and a non-recursive walk
    # would check only the root of `docs/` — that is, silently skip most
    # of the documentation.
    found = sorted(ROOT.rglob("docs/**/*.md"))
    found.append(ROOT / "README.md")
    return [path for path in found if path.exists()]


def references():
    out = []
    for document in documents():
        for line_number, line in enumerate(
            document.read_text(encoding="utf-8").splitlines(), start=1
        ):
            for match in REFERENCE.finditer(line):
                target = match.group(1) or match.group(2)
                out.append((document.relative_to(ROOT), line_number, target))
    return out


ALL = references()


def test_the_module_version_matches_cargo_toml():
    """The built module must name the version the manifest declares.

    The module lands in `site-packages` as a file, without package
    metadata, so the only way to identify the deployed copy is
    `__version__`. Its value comes from `CARGO_PKG_VERSION` at build
    time — and this check catches something else: that what sits in
    `site-packages` is TODAY'S build, not the one left over from the last
    release.
    """
    import paillier

    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version = "([^"]+)"', manifest, re.MULTILINE)
    assert declared, "no version line found in Cargo.toml"

    assert paillier.__version__ == declared.group(1), (
        f"the module was built as {paillier.__version__} while the manifest "
        f"declares {declared.group(1)} — site-packages holds an old build"
    )


def test_the_version_is_mentioned_in_the_changelog():
    """A release without a CHANGELOG entry is not a release."""
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', manifest, re.MULTILINE).group(1)

    assert f"## {version}" in changelog, (
        f"version {version} is declared in Cargo.toml, but CHANGELOG.md has "
        f"no section about it"
    )


def test_there_is_something_to_check():
    """Otherwise both tests below go green on an empty list.

    An assertion of absence — "not one broken link" — is true of a
    document with no links at all, and of a broken parser. The threshold
    sits below the actual count so it does not need rewriting on every
    edit to the documentation.
    """
    assert len(ALL) >= 5, f"{len(ALL)} references found, the parser is broken"


@pytest.mark.parametrize("document,line,target", ALL)
def test_the_reference_points_at_an_existing_file(document, line, target):
    assert (ROOT / target).exists(), (
        f"{document}:{line} names {target}, which does not exist"
    )


@pytest.mark.parametrize("document,line,target", ALL)
def test_the_reference_points_at_a_file_under_git(document, line, target):
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", target],
        capture_output=True,
    )
    assert tracked.returncode == 0, (
        f"{document}:{line} names {target}: the file is on disk but not in "
        f"the index — it will reach neither the tag nor a clone"
    )
