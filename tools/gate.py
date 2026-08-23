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

MAX_SHRINK = 0.20   # падение размера больше 20% против прошлого прогона — стоп
MAX_CONFLICTS = 40  # доменов сразу в двух категориях; на 23.08 у апстрима 17


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
            out.append((field, buf[pos:pos + length]))
            pos += length
        elif wire == 0:
            value, pos = read_varint(buf, pos)
            out.append((field, ("varint", value)))
        else:
            raise ValueError(f"неподдерживаемый wire type {wire}")
    return out


def parse_categories(blob, want_values):
    """→ {категория: (число записей, {значения} | None)}."""
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
                    for sub_field, sub in split_fields(chunk):
                        if sub_field == 2 and isinstance(sub, bytes):
                            try:
                                values.add(sub.decode())
                            except UnicodeDecodeError:
                                pass
        result[name] = (count, values)
    return result


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
        for name, domains in CANARIES.items():
            values = cats.get(name, (0, set()))[1] or set()
            missing = [d for d in domains if d not in values]
            if missing:
                failures.append(f"geosite: в {name} нет контрольных доменов: {', '.join(missing)}")

        # Сборщик geogaga категории между собой НЕ дедуплицирует: домен из двух
        # источников с разным dst попадает в обе категории, и дальше всё решает
        # порядок правил в шаблоне. На 23.08 таких 17 — это состояние апстрима
        # (реклама из category-ads runetfreedom против whitelist roscomvpn),
        # валить на нём сборку нельзя. Порог ловит регресс масштаба категории.
        direct = cats.get("GEOGAGA-DIRECT", (0, set()))[1] or set()
        total_conflicts = 0
        for other in ("GEOGAGA-PROXY", "GEOGAGA-BLOCK"):
            overlap = direct & (cats.get(other, (0, set()))[1] or set())
            total_conflicts += len(overlap)
            if overlap:
                print(f"  внимание: {len(overlap)} доменов сразу в DIRECT и {other}: "
                      f"{', '.join(sorted(overlap)[:8])}", file=sys.stderr)
        if total_conflicts > MAX_CONFLICTS:
            failures.append(f"geosite: конфликтов категорий {total_conflicts}, "
                            f"порог {MAX_CONFLICTS} — источник поехал")

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
