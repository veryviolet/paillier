"""The CI files must parse, and parse as intended.

A broken workflow fails SILENTLY: nothing breaks locally, and GitHub
answers "This run likely failed because of a workflow file issue" only
after the push, without naming a line. That is what happened to
`docs.yml`: the commit message was `"docs: deployed ..."`, and YAML read
the colon-plus-space inside an unquoted scalar as a nested mapping.

What is checked is not only parsing but the PRESENCE of the expected
triggers. A file that parses but has lost `workflow_dispatch` or `tags`
also breaks silently — just later.

`pyyaml` is required here rather than "if installed": `importorskip`
would turn this check into the very kind that is green because it never
ran.
"""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))

# YAML 1.1 reads a bare `on` as the boolean `true` — the line below is not
# a typo but what the key turns into after parsing.
ON = True


def test_there_is_something_to_check():
    assert len(WORKFLOWS) >= 3, f"found {len(WORKFLOWS)} CI files"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_it_parses(path):
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{path.name}: not a mapping"
    assert "jobs" in document, f"{path.name}: not a single job"
    assert ON in document, f"{path.name}: no trigger section"


def workflow(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text("utf-8"))


def test_publishing_is_tag_driven_and_may_use_oidc():
    document = workflow("publish.yml")

    assert "tags" in document[ON]["push"], "publishing must be driven by a tag"
    assert document["permissions"]["id-token"] == "write", (
        "without id-token: write the OIDC exchange does not happen, and "
        "Trusted Publishing silently becomes an authorisation failure at the "
        "very last step"
    )


def test_the_documentation_can_also_be_deployed_by_hand():
    document = workflow("docs.yml")

    assert "workflow_dispatch" in document[ON], (
        "without workflow_dispatch the documentation could only be deployed "
        "by cutting a new tag — and fixing a typo does not deserve one"
    )


def test_wheels_are_built_for_every_declared_version():
    """The CI matrix must match what pyproject promises.

    Drift here is silent in both directions: nobody will find a wheel for
    a version that is not in the classifiers, and a classifier without a
    wheel is a plain lie on the package page.
    """
    matrix = workflow("publish.yml")["jobs"]["build-wheels"]["strategy"]["matrix"]
    built = set(matrix["python"])

    manifest = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    promised = {
        line.split("::")[-1].strip().strip('",')
        for line in manifest.splitlines()
        if "Programming Language :: Python :: 3." in line
    }

    assert built == promised, (
        f"wheels are built for {sorted(built)}, while pyproject promises "
        f"{sorted(promised)}"
    )
