#!/usr/bin/env python3
"""Производные категории geosite — пост-шаг после builder.py, до хэшей и гейта.

GEOGAGA-PROXY-RU — записи GEOGAGA-PROXY, которые пересекаются с direct-правилом
шаблонов подписки (GEOGAGA-DIRECT ∪ EPICGAMES ∪ RIOT).

Зачем. В шаблоне правило `geosite:geogaga-proxy → proxy` стоит перед
direct-правилом, а в конце — catch-all → proxy. Значит, работу в PROXY делают
только записи, которые direct-правило перехватило бы (заблокированные домены
под `domain:ru`, конфликты вроде push.apple.com в apple), остальные ~53 000 и
без категории дошли бы до catch-all в туннель. Целиком GEOGAGA-PROXY (~75 000
записей) стоит клиентскому ядру ~36 МиБ пика при лимите NetworkExtension iOS
~50 МБ (замер 17.09.2026). Шаблон, переведённый на PROXY-RU, маршрутизирует
домены так же при вчетверо меньшей категории.

Запись E из PROXY попадает в PROXY-RU, если
  * E — keyword или regexp: берутся все, пересечение не вычислить;
  * значение E совпадает с какой-то записью фильтра (`covered(E, фильтр)`):
    `domain:grani.ru` при `domain:ru` в DIRECT;
  * E накрывает запись фильтра (`covered(D, [E])`, обратное вложение):
    PROXY `domain:x.com` при DIRECT `full:api.x.com` — без него api.x.com
    ушёл бы в direct, а сегодня уходит в proxy. Для keyword и regexp фильтра
    обратного вложения нет: их значение не домен.
Семантика совпадения — `covered()` из gate.py, та же, что в гейте (как у Xray).
Записи копируются protobuf-сообщениями целиком, атрибуты не теряются.

GEOGAGA-PROXY из базы не убирается никогда: база — надмножество, иначе откат
шаблона на прежнюю категорию потребует откатывать базу.

    python tools/derive.py geosite.dat               # дописать в тот же файл
    python tools/derive.py geosite.dat -o out.dat    # записать в другой

Код возврата 1 — нет исходной категории или производная вышла пустой; файл
тогда не пишется. Пороги размера и контрольные домены — в gate.py.
"""

import argparse
import collections
import os
import sys

import router_pb2
from gate import DOMAIN, FULL, PLAIN, REGEX, covered

SOURCE = "GEOGAGA-PROXY"
TARGET = "GEOGAGA-PROXY-RU"
# Категории direct-правила шаблонов Normal и Balancer (правило 10 на 25.09:
# geogaga-direct, domain:ru, domain:xn--p1ai, epicgames, riot; обе зоны лежат
# в GEOGAGA-DIRECT). Появится в direct-правиле новая категория — добавить сюда.
FILTER = ("GEOGAGA-DIRECT", "EPICGAMES", "RIOT")


def suffixes(domain):
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def derive(site_list):
    """→ (записи PROXY-RU в порядке PROXY, счётчики по причине)."""
    by_name = {e.country_code.upper(): e for e in site_list.entry}
    missing = [n for n in (SOURCE,) + FILTER if n not in by_name]
    if missing:
        raise SystemExit(f"derive: в базе нет категорий {', '.join(missing)} — {TARGET} не собрана")

    filt = [(d.type, d.value) for name in FILTER for d in by_name[name].domain]
    proxy = by_name[SOURCE].domain

    # Индексы — только чтобы не звать covered() на всех ~2000 записях фильтра
    # для каждой из ~75 000 записей PROXY. Кандидаты — все записи, которые
    # вообще могут совпасть: full с тем же значением, domain по суффиксам,
    # keyword и regexp целиком. Решение принимает covered().
    full_idx = collections.defaultdict(list)
    domain_idx = collections.defaultdict(list)
    loose = []
    for typ, value in filt:
        if typ == FULL:
            full_idx[value].append((typ, value))
        elif typ == DOMAIN:
            domain_idx[value].append((typ, value))
        else:
            loose.append((typ, value))

    keep = {}
    for i, d in enumerate(proxy):
        if d.type in (PLAIN, REGEX):
            keep[i] = "keyword/regexp"
            continue
        candidates = list(full_idx.get(d.value, ())) + loose
        for s in suffixes(d.value):
            candidates.extend(domain_idx.get(s, ()))
        if covered(d.value, candidates):
            keep[i] = "в фильтре"

    proxy_idx = collections.defaultdict(list)
    for i, d in enumerate(proxy):
        proxy_idx[d.value].append(i)
    for typ, value in filt:
        if typ not in (FULL, DOMAIN):
            continue
        for s in suffixes(value):
            for i in proxy_idx.get(s, ()):
                if i not in keep and covered(value, [(proxy[i].type, proxy[i].value)]):
                    keep[i] = "накрывает запись фильтра"

    reasons = collections.Counter(keep.values())
    return [proxy[i] for i in sorted(keep)], reasons


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("geosite", help="geosite.dat после builder.py")
    parser.add_argument("-o", "--output", help="куда писать (по умолчанию — тот же файл)")
    args = parser.parse_args()

    with open(args.geosite, "rb") as f:
        site_list = router_pb2.GeoSiteList.FromString(f.read())

    items, reasons = derive(site_list)
    if not items:
        raise SystemExit(f"derive: {TARGET} пуста — фильтр ничего не нашёл, файл не записан")

    # Повторный прогон на том же файле не должен давать вторую категорию.
    for i in reversed(range(len(site_list.entry))):
        if site_list.entry[i].country_code.upper() == TARGET:
            del site_list.entry[i]
    entry = site_list.entry.add()
    entry.country_code = TARGET
    entry.domain.extend(items)

    out = args.output or args.geosite
    tmp = out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(site_list.SerializeToString())
    os.replace(tmp, out)

    source = next(len(e.domain) for e in site_list.entry if e.country_code.upper() == SOURCE)
    detail = ", ".join(f"{why} {n}" for why, n in reasons.most_common())
    print(f"[DERIVE] {TARGET}: {len(items)} из {source} записей {SOURCE} ({detail}) → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
