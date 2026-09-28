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
    ушёл бы в direct, а сегодня уходит в proxy;
  * E — domain:, а keyword или regexp фильтра может совпасть с её поддоменом:
    PROXY `domain:example.com` при DIRECT `keyword:api` — api.example.com
    совпадает с обоими (ревью Codex T, 28.09.2026: до того такие записи
    выпадали, и поддомен уходил в direct). Keyword встречается в поддомене
    любой записи. Regexp доказывается двумя способами: однословный целиком
    (`^…$` без точки, dotless_whole) не совпадёт ни с одним поддоменом;
    привязанный к концу литеральным хвостом (`\\.ru$`, end_literal) — только
    с поддоменами записей X, у которых «.X» и хвост — суффиксы один другого.
    Недоказуемый regexp, как и keyword, оставляет все domain:; regexp,
    который Python читает не так, как Go, не проверить и на самой записи —
    тогда остаются и full:. PROXY-RU раздувается до PROXY, и гейт (верхний
    порог, youtube.com) её не пускает: стоп публикации лучше тихо сменённого
    маршрута. До второго способа (28.09) и `\\.ru$` в DIRECT останавливал
    сборку. На 25.09 в фильтре один regexp — однословное имя, поддомену он
    не совпадает, и эта ветка ничего не добавляет.
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
import re
import sys

try:
    from re import _parser as sre_parse  # Python 3.11+
except ImportError:
    import sre_parse

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


def opaque_regexp(pattern):
    """Regexp, который Python не компилирует или читает не так, как Go.

    Xray компилирует regexp на Go (RE2), а covered() и разбор ниже — Python.
    POSIX-класс Go `[[:punct:]]` Python принимает за набор букв, `\\pL` не
    знает вовсе: такой regexp не проверить ни на поддомене, ни на записи.
    """
    if "[:" in pattern:
        return True
    try:
        re.compile(pattern)
    except re.error:
        return True
    return False


DOT = ord(".")
BEGIN = {"AT_BEGINNING", "AT_BEGINNING_STRING"}
END = {"AT_END", "AT_END_STRING"}
# Классы без точки (\d \s \w) и их отрицания — с точкой; прочие неизвестны.
DOTLESS_CLASSES = {"CATEGORY_DIGIT", "CATEGORY_SPACE", "CATEGORY_WORD"}
DOTTED_CLASSES = {"CATEGORY_NOT_DIGIT", "CATEGORY_NOT_SPACE", "CATEGORY_NOT_WORD"}


def dotless_whole(pattern):
    """Regexp совпадает только со всей строкой (^…$), и точки в ней нет.

    Такой поддомену не совпадёт никогда: в поддомене точка есть всегда. Так
    устроен regexp direct-правила на 25.09 — `^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`.
    Разбор — парсером модуля re; что здесь не разобрано (любой символ,
    обратная ссылка, lookaround), считается «может поглотить точку».
    """
    if opaque_regexp(pattern):
        return False
    try:
        items = list(sre_parse.parse(pattern))
    except Exception:  # приватный модуль re: любой отказ — доказательства нет
        return False
    if len(items) < 2 or not (_anchor(items[0], BEGIN) and _anchor(items[-1], END)):
        return False
    return not _eats_dot(items)


def end_literal(pattern):
    """Литеральный хвост, которым кончается любая строка, совпавшая с regexp.

    `\\.ru$` → ".ru", `(^|\\.)vk\\.com$` → "vk.com". None — regexp не привязан к
    концу строки целиком (`a$|b` — нет), перед концом не литерал или разбор не
    удался. Хвост — в нижнем регистре: Xray сверяет домен в нижнем, а лишнее
    совпадение только оставляет запись в PROXY-RU.
    """
    if opaque_regexp(pattern):
        return None
    try:
        items = list(sre_parse.parse(pattern))
    except Exception:  # приватный модуль re: любой отказ — доказательства нет
        return None
    if len(items) < 2 or not _anchor(items[-1], END):
        return None
    tail = []
    for op, arg in reversed(items[:-1]):
        if _name(op) != "LITERAL":
            break
        tail.append(chr(arg))
    return "".join(reversed(tail)).lower() or None


def subdomain_may_end_with(value, tail):
    """Может ли поддомен записи domain:value — строка «….value» — кончаться на tail.

    Конец поддомена — «.value», перед ним что угодно: хвост короче сходится,
    только если он — конец «.value», длиннее — если «.value» — его конец.
    """
    dotted = "." + value
    return dotted.endswith(tail) or tail.endswith(dotted)


def _name(code):
    return getattr(code, "name", None)


def _anchor(item, names):
    op, arg = item
    return _name(op) == "AT" and _name(arg) in names


def _eats_dot(items):
    """Может ли кусок разобранного regexp поглотить «.»; незнакомое — может."""
    for op, arg in items:
        name = _name(op)
        if name == "AT":
            continue
        if name == "LITERAL":
            hit = arg == DOT
        elif name == "NOT_LITERAL":
            hit = arg != DOT
        elif name == "IN":
            hit = _class_has_dot(arg)
        elif name in ("SUBPATTERN", "MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            hit = _eats_dot(arg[-1])
        elif name == "ATOMIC_GROUP":
            hit = _eats_dot(arg)
        elif name == "BRANCH":
            hit = any(_eats_dot(alt) for alt in arg[1])
        else:
            return True
        if hit:
            return True
    return False


def _class_has_dot(items):
    """Есть ли «.» в классе [...]: литералы, диапазоны, \\d \\s \\w, отрицание."""
    negate = has = False
    for op, arg in items:
        name = _name(op)
        if name == "NEGATE":
            negate = True
        elif name == "LITERAL":
            has = has or arg == DOT
        elif name == "RANGE":
            has = has or arg[0] <= DOT <= arg[1]
        elif name == "CATEGORY" and _name(arg) in DOTLESS_CLASSES | DOTTED_CLASSES:
            has = has or _name(arg) in DOTTED_CLASSES
        else:
            return True
    return has != negate


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

    # Поддомены записей domain: против keyword и regexp фильтра (ревью Codex T,
    # 28.09.2026). Недоказуемое правило (wide) оставляет все domain:,
    # непрозрачный regexp — и full:; regexp с литеральным хвостом у конца
    # (tails) — только записи, чей поддомен может так кончаться. Каждое такое
    # правило — строка в лог.
    wide, tails = [], []
    for t, v in loose:
        if t == PLAIN:
            wide.append((t, v))
        elif not dotless_whole(v):
            tail = end_literal(v)
            if tail is None:
                wide.append((t, v))
            else:
                tails.append((v, tail))
    opaque = any(t == REGEX and opaque_regexp(v) for t, v in loose)
    by_tail = collections.Counter()
    for i, d in enumerate(proxy):
        if i in keep:
            continue
        if opaque or wide and d.type == DOMAIN:
            keep[i] = "может совпасть с keyword/regexp фильтра"
        elif d.type == DOMAIN:
            hit = next((v for v, tail in tails if subdomain_may_end_with(d.value, tail)), None)
            if hit is not None:
                keep[i] = "поддомен может совпасть с regexp фильтра"
                by_tail[hit] += 1
    for t, v in wide:
        print(f"derive: внимание — {'keyword' if t == PLAIN else 'regexp'}:{v} в фильтре "
              f"может совпасть с поддоменом любой записи domain:, в {TARGET} оставлены "
              "все; гейт раздутую категорию не пустит", file=sys.stderr)
    for v, tail in tails:
        print(f"derive: regexp:{v} в фильтре кончается на «{tail}» — оставлены записи domain:, "
              f"чей поддомен может так кончаться: {by_tail[v]}", file=sys.stderr)

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
