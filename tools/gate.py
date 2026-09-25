#!/usr/bin/env python3
"""Гейт качества geo-баз: проверка перед публикацией в S3.

Зачем: geogaga-client-flavor собирается из восьми апстримов. Если один из них
отдаст 404 или сменит имя категории, сборка молча пройдёт и выдаст базу
меньшего объёма. Наш s3-sync.sh пушит по смене sha256 и такого не заметит —
клиенты получат обрезанные правила и уедут в туннель мимо роутинга.

Проверяет: наличие и непустоту категорий, пороги по числу записей, падение
размера против прошлого удачного прогона, контрольные домены в нужных
категориях. Состояние прошлого прогона — рядом с файлом, в .geo-gate-state.

Использование:
    geo-gate.py --geosite output/geosite.dat --geoip output/geoip.dat
    geo-gate.py --geosite ... --geoip ... --state /var/lib/geo-gate.json

Код возврата: 0 — можно публиковать, 1 — нельзя. Встраивать в s3-sync.sh
ПЕРЕД PUT и в workflow форка ПЕРЕД публикацией релиза.
"""

import argparse
import json
import os
import re
import sys

# Пороги — примерно 85% от факта на 2026-08-23 (DIRECT 1911 после слияния
# с vahellame, PROXY 74824, BLOCK 832; geoip DIRECT 57644, PROXY 28172).
# Ниже порога — не деградация одного источника, а потеря целого апстрима.
MIN_ENTRIES = {
    "geosite": {"GEOGAGA-DIRECT": 1600, "GEOGAGA-PROXY": 63000, "GEOGAGA-BLOCK": 700},
    "geoip": {"GEOGAGA-DIRECT": 48000, "GEOGAGA-PROXY": 23000},
}

# Контрольные домены: по одному на смысловую группу источников.
# gosuslugi/alfa-bank — whitelist roscomvpn; app.avito.ru — донор vahellame;
# youtube/rutracker — ru-blocked runetfreedom; doubleclick — category-ads.
CANARIES = {
    "GEOGAGA-DIRECT": ["gosuslugi.ru", "alfa-bank.ru", "nalog.ru", "app.avito.ru", "api.samokat.ru"],
    "GEOGAGA-PROXY": ["youtube.com", "telegram.org", "rutracker.org"],
    "GEOGAGA-BLOCK": ["doubleclick.net"],
}

# Хвост roscomvpn (passthrough `*`→`*`): шаблоны подписки ссылаются на эти
# категории явно, без них правило в клиенте мёртвое. Верхняя граница ловит
# обвал passthrough: слияние с апстримом 21.09.2026 складывало все 22
# категории хвоста в одну (YOUTUBE стал 3056 вместо 177) — гейт по одним
# GEOGAGA-* и минимумам этого не заметил. Факт на 21.09: RIOT 54, EPICGAMES 27,
# YOUTUBE 177, TELEGRAM 26, GITHUB 28, GOOGLE-PLAY 29, TWITCH-ADS 5, TORRENT 418.
TAIL_ENTRIES = {
    "RIOT": (40, 300), "EPICGAMES": (20, 150), "YOUTUBE": (120, 900),
    "TELEGRAM": (20, 150), "GITHUB": (20, 150), "GOOGLE-PLAY": (20, 150),
    "TWITCH-ADS": (3, 40), "TORRENT": (300, 2000),
}

MAX_SHRINK = 0.20   # падение размера больше 20% против прошлого прогона — стоп
# Конфликты категорий разведены: они значат разное.
# DIRECT∩PROXY — противоречие маршрутизации, исход решает порядок правил;
#   таких быть почти не должно, порог жёсткий.
# DIRECT∩BLOCK — реклама и трекеры, попавшие в российские категории
#   (adfox.ru, webvisor.com и подобные). Блок-правило в шаблоне идёт первым,
#   поэтому исход правильный; порог мягкий, ловит только обвал масштаба категории.
MAX_CONFLICTS_PROXY = 25
MAX_CONFLICTS_BLOCK = 400


def read_varint(buf, pos):
    value = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def split_fields(buf):
    pos = 0
    out = []
    while pos < len(buf):
        key, pos = read_varint(buf, pos)
        wire, field = key & 7, key >> 3
        if wire == 2:
            length, pos = read_varint(buf, pos)
            # срез за концом буфера Python молча укорачивает: обрезанный файл
            # проходил гейт с теми же категориями (ревью Codex 24.09.2026)
            if pos + length > len(buf):
                raise ValueError(f"поле {field}: длина {length}, осталось {len(buf) - pos} байт — файл обрезан")
            out.append((field, buf[pos:pos + length]))
            pos += length
        elif wire == 0:
            value, pos = read_varint(buf, pos)
            out.append((field, ("varint", value)))
        else:
            raise ValueError(f"неподдерживаемый wire type {wire}")
    return out


# Тип правила Domain в router.proto: Plain (ключевое слово) = 0 — в protobuf
# не пишется, поле 1 отсутствует; Regex = 1; Domain (с поддоменами) = 2; Full = 3.
PLAIN, REGEX, DOMAIN, FULL = 0, 1, 2, 3


def parse_categories(blob, want_values):
    """→ {категория: (число записей, {(тип, значение)} | None)}."""
    result = {}
    for _, payload in split_fields(blob):
        name = None
        count = 0
        values = set() if want_values else None
        for field, chunk in split_fields(payload):
            if field == 1 and isinstance(chunk, bytes) and name is None:
                name = chunk.decode()
            elif field == 2 and isinstance(chunk, bytes):
                count += 1
                if want_values:
                    typ, value = PLAIN, None
                    for sub_field, sub in split_fields(chunk):
                        if sub_field == 1 and isinstance(sub, tuple):
                            typ = sub[1]
                        elif sub_field == 2 and isinstance(sub, bytes):
                            try:
                                value = sub.decode()
                            except UnicodeDecodeError:
                                pass
                    if value is not None:
                        values.add((typ, value))
        result[name] = (count, values)
    return result


def covered(domain, entries):
    """Домен совпадает с правилом категории так, как его совпадёт Xray.

    Сборщик geogaga схлопывает `full:app.avito.ru`, если в той же категории
    уже лежит `domain:avito.ru` — покрытие сохраняется, запись исчезает.
    Проверять точным совпадением значит ловить оптимизацию как поломку.
    Но тип важен: `full:avito.ru` поддомен app.avito.ru не покрывает — до
    25.09 гейт смотрел только на строку и такую потерю пропускал (ревью Codex).
    """
    parts = domain.split(".")
    suffixes = {".".join(parts[i:]) for i in range(len(parts))}
    for typ, value in entries:
        if typ == FULL and value == domain:
            return True
        if typ == DOMAIN and value in suffixes:
            return True
        if typ == PLAIN and value and value in domain:
            return True
        if typ == REGEX:
            try:
                if re.search(value, domain):
                    return True
            except re.error:
                pass
    return False


def check(kind, path, state, failures):
    if not os.path.exists(path):
        failures.append(f"{kind}: файла нет — {path}")
        return
    blob = open(path, "rb").read()
    size = len(blob)

    try:
        cats = parse_categories(blob, want_values=(kind == "geosite"))
    except (ValueError, IndexError) as exc:
        failures.append(f"{kind}: файл не разбирается ({exc})")
        return

    for name, minimum in MIN_ENTRIES[kind].items():
        if name not in cats:
            failures.append(f"{kind}: нет категории {name}")
            continue
        count = cats[name][0]
        if count < minimum:
            failures.append(f"{kind}: {name} — {count} записей, порог {minimum}")

    if kind == "geosite":
        for name, (low, high) in TAIL_ENTRIES.items():
            count = cats.get(name, (0, None))[0]
            if count < low:
                failures.append(f"geosite: хвост {name} — {count} записей, порог {low}")
            elif count > high:
                failures.append(f"geosite: хвост {name} — {count} записей, больше {high}: "
                                "passthrough свалил категории в одну")

        for name, domains in CANARIES.items():
            values = cats.get(name, (0, set()))[1] or set()
            missing = [d for d in domains if not covered(d, values)]
            if missing:
                failures.append(f"geosite: в {name} нет контрольных доменов: {', '.join(missing)}")

        # Сборщик geogaga категории между собой НЕ дедуплицирует: домен из двух
        # источников с разным dst попадает в обе категории, и дальше всё решает
        # порядок правил в шаблоне. На 23.08 таких 17 — это состояние апстрима
        # (реклама из category-ads runetfreedom против whitelist roscomvpn),
        # валить на нём сборку нельзя. Порог ловит регресс масштаба категории.
        def plain_values(cat):
            return {v for _, v in cats.get(cat, (0, set()))[1] or set()}

        direct = plain_values("GEOGAGA-DIRECT")
        for other, limit in (("GEOGAGA-PROXY", MAX_CONFLICTS_PROXY),
                             ("GEOGAGA-BLOCK", MAX_CONFLICTS_BLOCK)):
            overlap = direct & plain_values(other)
            if overlap:
                print(f"  внимание: {len(overlap)} доменов сразу в DIRECT и {other}: "
                      f"{', '.join(sorted(overlap)[:8])}", file=sys.stderr)
            if len(overlap) > limit:
                failures.append(f"geosite: {len(overlap)} доменов сразу в DIRECT и {other}, "
                                f"порог {limit} — источник поехал")

    previous = state.get(kind, {}).get("size")
    if previous and size < previous * (1 - MAX_SHRINK):
        failures.append(f"{kind}: размер {size} против {previous} в прошлый раз "
                        f"(падение {100 * (1 - size / previous):.0f}%)")

    state.setdefault(kind, {})["size"] = size
    print(f"{kind}: {size} байт, " + ", ".join(f"{n}={c}" for n, (c, _) in cats.items()),
          file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--geosite", required=True)
    parser.add_argument("--geoip", required=True)
    parser.add_argument("--state", default=None,
                        help="файл состояния (по умолчанию .geo-gate-state рядом с geosite)")
    args = parser.parse_args()

    state_path = args.state or os.path.join(os.path.dirname(os.path.abspath(args.geosite)),
                                            ".geo-gate-state")
    try:
        state = json.load(open(state_path))
    except (OSError, ValueError):
        state = {}

    failures = []
    check("geosite", args.geosite, state, failures)
    check("geoip", args.geoip, state, failures)

    if failures:
        print("\nГЕЙТ НЕ ПРОЙДЕН — публиковать нельзя:", file=sys.stderr)
        for line in failures:
            print(f"  ✗ {line}", file=sys.stderr)
        return 1

    # Состояние обновляем только на успехе: иначе просевший размер станет
    # новой нормой и следующая просадка пройдёт незамеченной.
    try:
        with open(state_path, "w") as handle:
            json.dump(state, handle)
    except OSError as exc:
        print(f"предупреждение: состояние не записано ({exc})", file=sys.stderr)

    print("гейт пройден", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
