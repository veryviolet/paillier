"""Файлы CI обязаны разбираться, и разбираться как задумано.

Битый workflow ломается МОЛЧА: локально ничего не падает, а GitHub
отвечает «This run likely failed because of a workflow file issue» уже
после пуша, без указания строки. Так и вышло с `docs.yml`: в сообщении
коммита стояло `"docs: выкачено ..."`, и двоеточие с пробелом внутри
незакавыченного скаляра YAML прочёл как вложенное отображение.

Проверяется не только разбор, но и НАЛИЧИЕ ожидаемых триггеров. Файл,
который разбирается, но потерял `workflow_dispatch` или `tags`, тоже
ломается молча — просто позже.

`pyyaml` здесь обязателен, а не «если установлен»: `importorskip`
превратил бы эту проверку в ту самую, которая зелена оттого, что не
выполнялась.
"""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))

# YAML 1.1 читает голое `on` как булево `true` — это не опечатка ниже, а
# то, во что превращается ключ после разбора.
ON = True


def test_есть_что_проверять():
    assert len(WORKFLOWS) >= 3, f"найдено {len(WORKFLOWS)} файлов CI"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_разбирается(path):
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{path.name}: не отображение"
    assert "jobs" in document, f"{path.name}: нет ни одной задачи"
    assert ON in document, f"{path.name}: нет секции триггеров"


def workflow(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text("utf-8"))


def test_публикация_идёт_по_тегу_и_имеет_право_на_oidc():
    document = workflow("publish.yml")

    assert "tags" in document[ON]["push"], "публикация обязана идти по тегу"
    assert document["permissions"]["id-token"] == "write", (
        "без id-token: write обмен OIDC не состоится, и Trusted Publishing "
        "молча превратится в отказ авторизации на последнем шаге"
    )


def test_документация_запускается_и_руками():
    document = workflow("docs.yml")

    assert "workflow_dispatch" in document[ON], (
        "без workflow_dispatch документацию нельзя выкатить иначе как "
        "новым тегом — а правка опечатки тега не заслуживает"
    )


def test_колёса_собираются_под_все_объявленные_версии():
    """Матрица CI обязана совпадать с тем, что обещано в pyproject.

    Разъезд здесь молчаливый в обе стороны: колесо для версии, которой
    нет в классификаторах, никто не найдёт; классификатор без колеса —
    прямая ложь в карточке пакета.
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
        f"колёса собираются под {sorted(built)}, а pyproject обещает "
        f"{sorted(promised)}"
    )
