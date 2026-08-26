"""Лицензионное состояние пакета — проверяемое, а не обещанное.

Повод конкретный. Колесо объявляло `MIT OR Apache-2.0`, тогда как GMP
входит в расширение СТАТИЧЕСКИ через `rug`, а `rug` и `gmp-mpfr-sys`
под LGPL-3.0+. То есть распространяемый бинарник — комбинированное
произведение по §4 LGPL, а метаданные об этом молчали.

Молчали бы и дальше: ничто в сборке не связывает набор зависимостей с
тем, что написано в `pyproject.toml`. Замена `rug` на другой бэкенд или
добавление ещё одной LGPL/GPL-зависимости прошли бы незамеченными до
первой претензии.

Проверяется поэтому НЕ текст, а соответствие: какие лицензии реально
есть в дереве зависимостей и что о них сказано.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Крейты, чья лицензия строже разрешительной, и потому обязаны быть
# названы. Проверяется по `Cargo.lock`, а не по памяти.
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
def test_файл_лицензии_на_месте(name):
    path = ROOT / name
    assert path.exists(), f"{name} обещан в pyproject, а файла нет"
    assert path.stat().st_size > 500, f"{name} подозрительно короток"


@pytest.mark.parametrize("name", REQUIRED_FILES)
def test_файл_лицензии_объявлен_в_pyproject(name):
    assert f'"{name}"' in pyproject(), (
        f"{name} лежит в репозитории, но не назван в license-files — "
        f"значит в колесо он не попадёт"
    )


def test_копилефт_из_зависимостей_отражён_в_выражении():
    """LGPL в дереве обязывает сказать это в метаданных.

    Именно эта проверка ловит исходный дефект: `rug` в `Cargo.lock`
    есть, GMP вкомпилирована статически, а выражение обещало только
    разрешительные лицензии.
    """
    present = COPYLEFT & cargo_lock_crates()
    assert present, (
        "ни rug, ни gmp-mpfr-sys нет в Cargo.lock — если бэкенд длинной "
        "арифметики сменился, эту проверку надо переписать, а не удалить"
    )

    declared = re.search(r'^license = "([^"]+)"', pyproject(), re.MULTILINE)
    assert declared, "в pyproject нет выражения лицензии"

    assert "LGPL-3.0-or-later" in declared.group(1), (
        f"в зависимостях есть {sorted(present)} под LGPL-3.0+, а колесо "
        f"объявляет {declared.group(1)}: GMP входит в расширение "
        f"статически, значит это комбинированное произведение"
    )


def test_уведомление_называет_каждую_копилефт_зависимость():
    notice = (ROOT / "NOTICE.md").read_text(encoding="utf-8")
    for name in sorted(COPYLEFT & cargo_lock_crates()):
        assert name in notice, f"{name} не назван в NOTICE.md"


def test_уведомление_названо_читателю():
    """§4(a) LGPL требует ЗАМЕТНОГО уведомления, а не файла в углу."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "NOTICE.md" in readme or "LGPL" in readme, (
        "README не упоминает ни NOTICE.md, ни LGPL — уведомление, "
        "которое никто не увидит, уведомлением не является"
    )


def test_fast_paillier_только_в_dev_зависимостях():
    """Он эталон в тестах и в сборку библиотеки входить не должен.

    Переезд его в обычные зависимости изменил бы и состав колеса, и
    лицензионную картину — молча.
    """
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    dev = manifest.index("[dev-dependencies]")

    assert "fast-paillier" not in manifest[:dev], (
        "fast-paillier попал в обычные зависимости: он эталон для "
        "тестов, а не часть библиотеки"
    )
    assert "fast-paillier" in manifest[dev:]


def test_собранное_расширение_не_содержит_кода_эталона():
    """Проверка не по манифесту, а по БИНАРНИКУ.

    Манифест говорит о намерении, бинарник — о том, что уехало
    пользователю.
    """
    import paillier

    # Сам файл модуля, а не первый .so из каталога. Модуль ставится и
    # пакетом (`paillier/paillier.*.so`), и голым расширением
    # (`site-packages/paillier.so`), и во втором случае `parent` — это
    # весь `site-packages`: первая же итерация `glob` подобрала бы
    # чужую библиотеку и объявила бы наш бинарник грязным. Так этот
    # тест и упал в первый раз.
    module = Path(paillier.__file__)
    if module.suffix in {".so", ".pyd"}:
        binary = module
    else:
        found = sorted(module.parent.glob("paillier*.so")) or sorted(
            module.parent.glob("paillier*.pyd")
        )
        if not found:
            pytest.skip("модуль собран не как расширение — проверять нечего")
        binary = found[0]

    blob = binary.read_bytes()
    assert b"fast_paillier" not in blob and b"fast-paillier" not in blob, (
        "код эталона попал в собранное расширение"
    )
    # А GMP — попал, и это ровно то, ради чего заведён NOTICE.md.
    assert b"GNU MP" in blob, (
        "GMP не нашлась в бинарнике: если линковка стала динамической, "
        "лицензионное положение изменилось и NOTICE.md надо переписать"
    )


def test_версия_rug_не_прибита_намертво():
    """§4(d)(0) LGPL: пользователь должен мочь пересобрать с ДРУГОЙ
    версией библиотеки.

    Точное закрепление (`=1.30.0`) этому мешает: пересборка со своей
    сборкой GMP потребовала бы править наш манифест.
    """
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    rug = re.search(r'^rug = "([^"]+)"', manifest, re.MULTILINE)

    assert rug, "строка зависимости rug не найдена"
    assert not rug.group(1).startswith("="), (
        f"rug закреплён как {rug.group(1)}: точное закрепление мешает "
        f"пересборке с другой версией, которой требует §4(d) LGPL"
    )


def test_сторонний_код_упомянут_в_обеих_ролях():
    """`heu` в зависимости не входит, но приёмы взяты оттуда.

    Не назвать источник — не нарушение авторского права (алгоритмы им не
    охраняются), но умолчание здесь хуже бесполезного.
    """
    notice = (ROOT / "NOTICE.md").read_text(encoding="utf-8")

    assert "heu" in notice, "heu не назван в NOTICE.md"
    assert subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "NOTICE.md"],
        capture_output=True,
    ).returncode == 0, "NOTICE.md не в индексе — в колесо не попадёт"
