#!/usr/bin/env python3
"""Тесты derive.py, gate.py и шага базовой линии в build.yaml.

Инвариант derive.py: шаблон с `geogaga-proxy-ru → proxy` перед direct-правилом
(GEOGAGA-DIRECT ∪ EPICGAMES ∪ RIOT) и catch-all → proxy в конце ведёт любой
домен туда же, куда и с полной `geogaga-proxy`, включая поддомены записей
domain:. Сквозная проверка на реальной базе — derive → gate → маршрут: гейт
пропускает только базу, где маршрут не сменился (ревью Codex T, 28.09.2026:
`keyword:api` в DIRECT уводил api.example.com в direct, а гейт молчал).
Шаг базовой линии: не прочиталась ветка release — сборка падает, а не идёт
без проверки усадки; первая публикация — только с first_release.

    python3 tools/test_derive_gate.py -v
    git show origin/release:geosite.dat > /tmp/geosite.dat
    GEOSITE=/tmp/geosite.dat python3 tools/test_derive_gate.py -v   # и реальная база

Ни protoc, ни protobuf не нужны: базу разбирает gate.split_fields, как в
гейте. Тест шагов workflow зовёт bash и берёт шаги из YAML — без PyYAML
пропускается.

В CI с 28.09: workflow «0. Тесты derive и гейта» (test.yaml) — на каждый пуш
в tools/ и .github/, на опубликованном релизе; сборка (build.yaml) — перед
сборщиком и RealBaseTest на своей свежей базе до публикации.
"""

import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import router_pb2  # noqa: F401 — есть после protoc, как в workflow
except ImportError:  # derive() он не нужен, только main()
    sys.modules["router_pb2"] = types.ModuleType("router_pb2")

import derive  # noqa: E402
import gate  # noqa: E402
from gate import DOMAIN, FULL, PLAIN, REGEX  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

WORKFLOW = os.path.join(HERE, "..", ".github", "workflows", "build.yaml")
TYPES = {"keyword": PLAIN, "regexp": REGEX, "domain": DOMAIN, "full": FULL}
NO_BASELINE = "нет размера прошлой сборки"


def rules(*lines):
    """'domain:x.com', 'regexp:^a\\.' → [(тип, значение)]."""
    return [(TYPES[kind], value) for kind, value in (line.split(":", 1) for line in lines)]


def site_list(cats):
    """{категория: [(тип, значение)]} → то, что derive() читает у GeoSiteList."""
    return types.SimpleNamespace(entry=[
        types.SimpleNamespace(country_code=name, domain=[
            types.SimpleNamespace(type=t, value=v) for t, v in entries])
        for name, entries in cats.items()])


def run_derive(cats):
    """→ записи GEOGAGA-PROXY-RU как [(тип, значение)]; «внимание» derive глушится."""
    with contextlib.redirect_stderr(io.StringIO()):
        items = derive.derive(site_list(cats))[0]
    return [(d.type, d.value) for d in items]


class Category:
    """Совпадение, как у Xray: full — равенство, domain — домен и поддомены,
    keyword — подстрока, regexp — поиск. Отдельно от covered() и с индексами:
    реальная база — ~75 000 записей и сотни тысяч проб."""

    def __init__(self, entries):
        entries = list(entries)
        self.full = {v for t, v in entries if t == FULL}
        self.domain = {v for t, v in entries if t == DOMAIN}
        words = [re.escape(v) for t, v in entries if t == PLAIN]
        self.keyword = re.compile("|".join(words)) if words else None
        self.regexp = [re.compile(v) for t, v in entries if t == REGEX]

    def __contains__(self, name):
        labels = name.split(".")
        return (name in self.full
                or any(".".join(labels[i:]) in self.domain for i in range(len(labels)))
                or bool(self.keyword and self.keyword.search(name))
                or any(r.search(name) for r in self.regexp))


def route(name, proxy, direct):
    """Шаблон Normal/Balancer: proxy-категория → proxy, direct-правило → direct,
    catch-all → proxy."""
    if name in proxy:
        return "proxy"
    return "direct" if name in direct else "proxy"


def changed_routes(cats, ru, probes):
    """Пробы, которые с PROXY-RU уходят не туда, куда с полной PROXY."""
    full, short = Category(cats["GEOGAGA-PROXY"]), Category(ru)
    direct = Category(e for name in derive.FILTER for e in cats[name])
    return sorted(p for p in probes if route(p, short, direct) != route(p, full, direct))


def decode(blob):
    """Байты GeoSiteList → {категория: [(тип, значение)]} в порядке файла."""
    cats = {}
    for _, site in gate.split_fields(blob):
        name, entries = None, []
        for num, chunk in gate.split_fields(site):
            if num == 1 and name is None:
                name = chunk.decode()
            elif num == 2:
                typ, value = PLAIN, ""
                for sub, part in gate.split_fields(chunk):
                    if sub == 1:
                        typ = part[1]
                    elif sub == 2:
                        value = part.decode()
                entries.append((typ, value))
        cats[name] = entries
    return cats


def varint(n):
    out = bytearray()
    while n > 0x7F:
        out.append(n & 0x7F | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def field(num, payload):
    return varint(num << 3 | 2) + varint(len(payload)) + payload


def encode(cats):
    """{категория: [(тип, значение)]} → байты GeoSiteList, без атрибутов."""
    out = bytearray()
    for name, entries in cats.items():
        body = bytearray(field(1, name.encode()))
        for typ, value in entries:
            kind = varint(1 << 3) + varint(typ) if typ else b""
            body += field(2, kind + field(2, value.encode()))
        out += field(1, bytes(body))
    return bytes(out)


def run_gate(*flags, state=None):
    """gate.main() на пустых базах: → (код, stderr). Пустой файл — усадка 100 %."""
    with tempfile.TemporaryDirectory() as tmp:
        geosite, geoip, state_path = (os.path.join(tmp, n)
                                      for n in ("geosite.dat", "geoip.dat", "state.json"))
        for path in (geosite, geoip):
            open(path, "wb").close()
        if state is not None:
            with open(state_path, "w") as f:
                f.write(state)
        argv = ["gate.py", "--geosite", geosite, "--geoip", geoip, "--state", state_path, *flags]
        err = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(err):
            code = gate.main()
    return code, err.getvalue()


class DeriveTest(unittest.TestCase):
    """Синтетика: фильтр — GEOGAGA-DIRECT, EPICGAMES и RIOT пустые."""

    def derive_and_route(self, proxy, direct, probes):
        cats = {"GEOGAGA-PROXY": rules(*proxy), "GEOGAGA-DIRECT": rules(*direct),
                "EPICGAMES": [], "RIOT": []}
        ru = run_derive(cats)
        self.assertEqual(changed_routes(cats, ru, probes), [])
        return ru

    def test_keyword_in_direct_keeps_parent(self):
        # сценарий Codex: сам example.com keyword не содержит, api.example.com — да
        ru = self.derive_and_route(
            ["domain:example.com", "domain:youtube.com"], ["domain:ru", "keyword:api"],
            ["example.com", "api.example.com", "x.api.example.com", "youtube.com",
             "rapid.youtube.com"])
        self.assertIn((DOMAIN, "example.com"), ru)

    def test_regexp_in_direct_keeps_parent(self):
        ru = self.derive_and_route(["domain:example.com"], [r"regexp:^api\."],
                                   ["example.com", "api.example.com"])
        self.assertIn((DOMAIN, "example.com"), ru)

    def test_single_label_regexp_adds_nothing(self):
        # regexp GEOGAGA-DIRECT на 25.09 — однословное имя: поддомену не совпадёт,
        # иначе PROXY-RU раздулась бы до PROXY и гейт встал бы на каждой сборке
        ru = self.derive_and_route(
            ["domain:youtube.com", "domain:onion", "full:telegram.org"],
            [r"regexp:^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"],
            ["youtube.com", "www.youtube.com", "onion", "x.onion", "telegram.org", "localhost"])
        self.assertEqual(ru, rules("domain:onion"))

    def test_opaque_regexp_keeps_full_too(self):
        # \pL — синтаксис Go, Python его не компилирует: не проверить и саму запись
        ru = run_derive({"GEOGAGA-PROXY": rules("domain:youtube.com", "full:telegram.org"),
                         "GEOGAGA-DIRECT": rules(r"regexp:^\pL+\.org$"),
                         "EPICGAMES": [], "RIOT": []})
        self.assertEqual(ru, rules("domain:youtube.com", "full:telegram.org"))

    def test_end_anchored_regexp_keeps_only_fitting_tails(self):
        # до 28.09 любой regexp, кроме однословного, оставлял все domain:, и
        # `\.ru$` в DIRECT раздувал PROXY-RU до PROXY — гейт вставал. Хвост у
        # конца доказывает: поддомены other.com и youtube.com так не кончаются;
        # domain:ru — сама «ru» без точки, но x.ru совпадает
        ru = self.derive_and_route(
            ["domain:example.com", "domain:other.com", "domain:youtube.com", "domain:ru"],
            [r"regexp:\.ru$", r"regexp:^[a-z]+\.example\.com$"],
            ["example.com", "www.example.com", "other.com", "www.other.com", "youtube.com",
             "m.youtube.com", "ru", "x.ru", "a.b.ru"])
        self.assertEqual(ru, rules("domain:example.com", "domain:ru"))

    def test_tail_longer_than_entry(self):
        # хвост «vk.com» длиннее «.com»: поддомен vk.com записи domain:com совпадает
        ru = self.derive_and_route(
            ["domain:com", "domain:vk.com", "domain:example.com"], [r"regexp:(^|\.)vk\.com$"],
            ["com", "vk.com", "m.vk.com", "xvk.com", "example.com", "www.example.com"])
        self.assertEqual(ru, rules("domain:com", "domain:vk.com"))

    def test_tail_ignores_case(self):
        # (?i): хвост сверяется в нижнем регистре, иначе x.ru ушёл бы в direct
        ru = self.derive_and_route(["domain:ru", "domain:example.com"], [r"regexp:(?i)\.RU$"],
                                   ["ru", "x.ru", "example.com", "www.example.com"])
        self.assertEqual(ru, rules("domain:ru"))

    def test_unprovable_tails(self):
        # не привязан к концу целиком, перед концом не литерал — доказательства нет
        for pattern in (r"\.ru$|^api\.", r"[a-z]$", r"^api\.", r"\.ru"):
            self.assertIsNone(derive.end_literal(pattern), pattern)
        self.assertEqual(derive.end_literal(r"(^|\.)vk\.com$"), "vk.com")
        self.assertEqual(derive.end_literal(r"\.RU\Z"), ".ru")

    def test_wide_rule_is_reported(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            derive.derive(site_list({"GEOGAGA-PROXY": rules("domain:example.com"),
                                     "GEOGAGA-DIRECT": rules("keyword:api"),
                                     "EPICGAMES": [], "RIOT": []}))
        self.assertIn("keyword:api", err.getvalue())

    def test_previous_rules_hold(self):
        # запись под domain: фильтра, накрытие full: фильтра, keyword PROXY целиком
        ru = self.derive_and_route(
            ["domain:grani.ru", "domain:x.com", "domain:youtube.com", "keyword:torrent"],
            ["domain:ru", "full:api.x.com"],
            ["grani.ru", "www.grani.ru", "x.com", "api.x.com", "youtube.com", "torrent.example"])
        self.assertEqual(ru, rules("domain:grani.ru", "domain:x.com", "keyword:torrent"))


class GateStateTest(unittest.TestCase):
    """--require-state: без базовой линии гейт отказывает сам."""

    def test_missing_state_fails_with_flag(self):
        code, err = run_gate("--require-state")
        self.assertEqual(code, 1)
        self.assertIn(NO_BASELINE, err)

    def test_broken_state_fails_with_flag(self):
        # printf с пустыми размерами дал бы битый JSON — это тоже не база
        _, err = run_gate("--require-state", state='{"geosite": {"size": }, "geoip": {"size": }}')
        self.assertIn(NO_BASELINE, err)

    def test_missing_state_is_first_run_without_flag(self):
        _, err = run_gate()
        self.assertNotIn(NO_BASELINE, err)

    def test_baseline_catches_shrink(self):
        _, err = run_gate("--require-state",
                          state='{"geosite": {"size": 1000}, "geoip": {"size": 1000}}')
        self.assertNotIn(NO_BASELINE, err)
        self.assertIn("падение 100%", err)


def cidr(ip, prefix):
    """CIDR geoip: ip — байты адреса, prefix 0 в protobuf не пишется."""
    return field(1, ip) + (varint(2 << 3) + varint(prefix) if prefix else b"")


class GateGeoipTest(unittest.TestCase):
    """gate.check("geoip"): записи CIDR разбираются, а не только считаются.
    До 02.10 GEOGAGA-DIRECT/PROXY с нужными количествами и оборванным
    protobuf каждой записи проходили гейт (ревью Codex F2)."""

    GOOD = cidr(bytes([10, 0, 0, 0]), 24)

    def check(self, bad=None):
        """База с порогами впритык; bad — одна запись PROXY вместо годной."""
        sizes = gate.MIN_ENTRIES["geoip"]
        out = bytearray()
        for name, count in sizes.items():
            entries = [self.GOOD] * count
            if bad is not None and name == "GEOGAGA-PROXY":
                entries[count // 2] = bad
            out += field(1, field(1, name.encode()) + b"".join(field(2, e) for e in entries))
        failures = []
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "geoip.dat")
            with open(path, "wb") as f:
                f.write(out)
            with contextlib.redirect_stderr(io.StringIO()):
                gate.check("geoip", path, {}, failures)
        return failures

    def test_valid_base_passes(self):
        self.assertEqual(self.check(), [])
        self.assertEqual(self.check(cidr(bytes(16), 128)), [])
        self.assertEqual(self.check(cidr(bytes(4), 0)), [])

    def test_broken_cidr_fails(self):
        for name, bad in (("оборванный protobuf", b"\xff"),
                          ("адрес 5 байт", cidr(bytes(5), 24)),
                          ("адреса нет", varint(2 << 3) + varint(24)),
                          ("prefix 33 у IPv4", cidr(bytes(4), 33)),
                          ("prefix 129 у IPv6", cidr(bytes(16), 129)),
                          ("ip не байтами", varint(1 << 3) + varint(10))):
            with self.subTest(name):
                failures = self.check(bad)
                self.assertEqual(len(failures), 1, failures)
                self.assertIn("geoip: файл не разбирается", failures[0])


@unittest.skipUnless(yaml, "нужен PyYAML")
class WorkflowBaselineTest(unittest.TestCase):
    """Шаги build.yaml в bash -e, как их зовёт GitHub, с подставными git, sleep
    и python."""

    BASE = "Базовая линия гейта — размеры опубликованного релиза"
    GATE = "Гейт качества geo-баз"

    @classmethod
    def setUpClass(cls):
        with open(WORKFLOW, encoding="utf-8") as f:
            steps = yaml.safe_load(f)["jobs"]["build"]["steps"]
        cls.steps = {s.get("name"): s.get("run") for s in steps}

    def run_step(self, name, git="exit 128", first_release=""):
        """→ (процесс, содержимое gate-state.json или None)."""
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = os.path.join(tmp, "bin")
            os.mkdir(bin_dir)
            for tool, body in (("git", git), ("sleep", "exit 0"), ("python", 'echo "python $*"')):
                path = os.path.join(bin_dir, tool)
                with open(path, "w") as f:
                    f.write(f"#!/bin/sh\n{body}\n")
                os.chmod(path, 0o755)
            env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ["PATH"],
                       RUNNER_TEMP=tmp, FIRST_RELEASE=first_release)
            proc = subprocess.run(["bash", "-e", "-c", self.steps[name]], env=env,
                                  capture_output=True, text=True, timeout=60)
            state_path = os.path.join(tmp, "gate-state.json")
            state = None
            if os.path.exists(state_path):
                with open(state_path) as f:
                    state = f.read()
        return proc, state

    def test_unread_release_fails_build(self):
        proc, state = self.run_step(self.BASE)
        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("::error::", proc.stdout)
        self.assertIsNone(state)

    def test_first_release_allows_missing_baseline(self):
        proc, state = self.run_step(self.BASE, first_release="true")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("::warning::", proc.stdout)
        self.assertIsNone(state)

    def test_baseline_reaches_gate(self):
        # шаг пишет размеры релиза, гейт по ним ловит усадку
        proc, state = self.run_step(
            self.BASE, git='case "$1" in fetch) exit 0 ;; cat-file) echo 1000 ;; esac')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        _, err = run_gate("--require-state", state=state)
        self.assertNotIn(NO_BASELINE, err)
        self.assertIn("падение 100%", err)

    def test_gate_requires_state_except_first_release(self):
        proc, _ = self.run_step(self.GATE)
        self.assertIn("--require-state", proc.stdout)
        proc, _ = self.run_step(self.GATE, first_release="true")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("--require-state", proc.stdout)


@unittest.skipUnless(os.environ.get("GEOSITE"), "реальная база: GEOSITE=путь к geosite.dat")
class RealBaseTest(unittest.TestCase):
    """derive → gate → маршрут на опубликованной базе."""

    @classmethod
    def setUpClass(cls):
        with open(os.environ["GEOSITE"], "rb") as f:
            cls.cats = decode(f.read())

    def publish(self, cats):
        """derive → файл → gate.check: → (PROXY-RU, провалы гейта по geosite)."""
        ru = run_derive(cats)
        out = dict(cats)
        out[derive.TARGET] = ru
        failures = []
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "geosite.dat")
            with open(path, "wb") as f:
                f.write(encode(out))
            with contextlib.redirect_stderr(io.StringIO()):
                gate.check("geosite", path, {}, failures)
        return ru, failures

    @staticmethod
    def probes(cats):
        """Записи domain:/full: PROXY и фильтра, их поддомены www. и api."""
        names = set()
        for name in ("GEOGAGA-PROXY",) + derive.FILTER:
            for typ, value in cats[name]:
                if typ in (DOMAIN, FULL):
                    names.update((value, "www." + value, "api." + value))
        return names

    def test_published_base_keeps_routes(self):
        ru, failures = self.publish(self.cats)
        self.assertEqual(failures, [])
        self.assertEqual(changed_routes(self.cats, ru, self.probes(self.cats))[:10], [])

    def test_file_category_is_derived(self):
        # в сборке — категория в только что собранном файле; на опубликованном
        # релизе расхождение значит, что derive.py сменил вывод, — до следующей
        # сборки это ожидаемо, но должно быть намеренным
        if derive.TARGET not in self.cats:
            self.skipTest(f"в базе нет {derive.TARGET}")
        self.assertEqual(self.cats[derive.TARGET], run_derive(self.cats),
                         f"{derive.TARGET} в файле ≠ derive по этому же файлу")

    def test_end_anchored_regexp_in_direct_passes_gate(self):
        # `\.ru$` в DIRECT: до 28.09 PROXY-RU раздувалась до PROXY и гейт вставал;
        # теперь категория та же — поддомены на .ru и так под domain:ru фильтра
        cats = dict(self.cats)
        cats["GEOGAGA-DIRECT"] = cats["GEOGAGA-DIRECT"] + rules(r"regexp:\.ru$")
        ru, failures = self.publish(cats)
        self.assertEqual(failures, [])
        self.assertEqual(len(ru), len(run_derive(self.cats)))
        self.assertEqual(changed_routes(cats, ru, self.probes(cats))[:10], [])

    def test_keyword_in_direct_blocked_or_harmless(self):
        # сценарий Codex на живых данных: keyword:api в DIRECT
        cats = dict(self.cats)
        cats["GEOGAGA-DIRECT"] = cats["GEOGAGA-DIRECT"] + rules("keyword:api")
        ru, failures = self.publish(cats)
        if not failures:  # гейт пропустил — тогда маршрут обязан сохраниться
            self.assertEqual(changed_routes(cats, ru, self.probes(cats))[:10], [])


if __name__ == "__main__":
    unittest.main()
