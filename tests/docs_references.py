"""Всё, на что ссылается документация, существует И лежит под git.

Проверка появилась после двух поломок в одном документе:
`benches/timing_by_weight.rs` был назван прогоном, «оставленным в
репозитории», хотя прогон давно переехал в `tests/timing_channel.rs`; а
замеры точности документ звал по путям во временном каталоге, который
до читателя не доезжает вовсе.

Две проверки, а не одна, и вторая важнее. Файл может лежать на диске у
меня и отсутствовать в индексе — тогда он не попадёт ни в тег, ни в
клон, и ссылка сломается ровно у того, кто пришёл читать. Так уже
уезжал релиз без двух файлов.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Ссылка на файл репозитория в двух формах сразу: путь в обратных
# кавычках и цель markdown-ссылки `[текст](путь)`. Вторая форма нужна не
# для полноты: README ссылается на документы именно так, и с одной лишь
# первой формой он проверялся ВПУСТУЮ — путей в кавычках в нём не было
# ни одного, и битую ссылку там никто бы не увидел.
#
# Строка кода (`Cargo.toml`) сюда не попадает намеренно: предмет
# проверки в том, что дока зовёт РАЗДЕЛЫ репозитория, которых нет.
REFERENCE = re.compile(
    r"`((?:src|tests|benches|docs)/[A-Za-z0-9_./-]+)`"
    r"|\]\(((?:src|tests|benches|docs)/[A-Za-z0-9_./-]+)\)"
)


def documents():
    found = sorted(ROOT.glob("docs/*.md"))
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


def test_версия_модуля_совпадает_с_cargo_toml():
    """Собранный модуль обязан называть ту версию, что в манифесте.

    Модуль кладётся в `site-packages` файлом, без метаданных пакета,
    поэтому опознать выкаченную копию можно только по `__version__`.
    Значение берётся из `CARGO_PKG_VERSION` на сборке — а проверка
    ловит другое: что в `site-packages` лежит СЕГОДНЯШНЯЯ сборка, а не
    та, что осталась от прошлого выпуска.
    """
    import paillier

    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version = "([^"]+)"', manifest, re.MULTILINE)
    assert declared, "в Cargo.toml не нашлась строка версии"

    assert paillier.__version__ == declared.group(1), (
        f"модуль собран как {paillier.__version__}, а манифест объявляет "
        f"{declared.group(1)} — в site-packages старая сборка"
    )


def test_версия_упомянута_в_changelog():
    """Выпуск без записи в CHANGELOG — не выпуск."""
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', manifest, re.MULTILINE).group(1)

    assert f"## {version}" in changelog, (
        f"версия {version} объявлена в Cargo.toml, но раздела о ней в "
        f"CHANGELOG.md нет"
    )


def test_есть_что_проверять():
    """Иначе оба теста ниже зеленеют на пустом списке.

    Утверждение об отсутствии — «ни одной битой ссылки» — верно и для
    документа без ссылок вообще, и для сломанного разбора. Порог
    поставлен ниже фактического числа, чтобы не переписывать его на
    каждую правку доки.
    """
    assert len(ALL) >= 5, f"ссылок найдено {len(ALL)}, разбор сломан"


@pytest.mark.parametrize("document,line,target", ALL)
def test_ссылка_ведёт_к_существующему_файлу(document, line, target):
    assert (ROOT / target).exists(), f"{document}:{line} зовёт {target}, а его нет"


@pytest.mark.parametrize("document,line,target", ALL)
def test_ссылка_ведёт_к_файлу_под_git(document, line, target):
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", target],
        capture_output=True,
    )
    assert tracked.returncode == 0, (
        f"{document}:{line} зовёт {target}: файл есть на диске, но не в "
        f"индексе — в тег и в клон он не попадёт"
    )
