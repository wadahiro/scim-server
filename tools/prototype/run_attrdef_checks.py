#!/usr/bin/env python3
"""層 A-1 で抽出した必須メンバ定義を、実際の SCIM サーバに対して検査する。

無条件 REQUIRED だけを合否判定に使う。条件付き（"REQUIRED if ...", "when ..."）は
条件を機械的に評価できないので SKIP にし、条件文をそのまま表示する。
各検査は根拠の RFC・節・行範囲を必ず持つ。
"""
import json, sys, urllib.request, urllib.error

# 抽出結果の属性定義を、どのエンドポイントの何に当てるかの対応。
# 節 -> (取得パス, 検査対象の取り出し方)
TARGETS = {
    ('7643', '5'):     ('/ServiceProviderConfig', 'single'),
    ('7643', '6'):     ('/ResourceTypes',         'list'),
    ('7643', '7'):     ('/Schemas',               'list'),
    ('7644', '3.4.2'): ('/Users?count=1',         'envelope'),
}

def get(base, path):
    r = urllib.request.Request(base + path,
                               headers={'Accept': 'application/scim+json'})
    try:
        with urllib.request.urlopen(r) as x:
            return x.status, json.loads(x.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')

# 「親が存在しない」と「親は存在するが子が無い」の区別。
ABSENT_PARENT, MISSING, OK = 'absent_parent', 'missing', 'ok'

def present(obj, dotted):
    """"a.b" を辿る。途中が配列なら全要素に存在することを求める。

    親（最後の要素より手前）が不在なら ABSENT_PARENT を返す。親自体が OPTIONAL の
    場合、子の REQUIRED は「親があるとき」の条件付き要求なので FAIL にできない。
    """
    parts = dotted.split('.')
    cur = [obj]
    for part in parts[:-1]:
        nxt = []
        for c in cur:
            if not isinstance(c, dict) or part not in c:
                return ABSENT_PARENT
            v = c[part]
            nxt.extend(v if isinstance(v, list) else [v])
        if not nxt:
            return ABSENT_PARENT      # 空配列 → 要素が無いので問えない
        cur = nxt
    last = parts[-1]
    for c in cur:
        if not isinstance(c, dict) or last not in c:
            return MISSING
    return OK

def main(base, defs_path):
    defs = json.load(open(defs_path))
    rows = []
    cache = {}
    for d in defs:
        key = (str(d['rfc']), d['section'])
        if key not in TARGETS:
            continue
        path, shape = TARGETS[key]
        if path not in cache:
            cache[path] = get(base, path)
        status, body = cache[path]
        attr = d['attribute']

        if d['conditional']:
            rows.append((d, 'SKIP', f"条件付き: {d['condition']}"))
            continue
        if d['cardinality'] != 'REQUIRED':
            rows.append((d, 'INFO', f"{d['cardinality']}（合否対象外）"))
            continue
        if status != 200:
            rows.append((d, 'ERROR', f"GET {path} -> {status}")); continue

        def verdict_for(targets, label):
            res = [present(t, attr) for t in targets]
            miss = res.count(MISSING)
            noparent = res.count(ABSENT_PARENT)
            if miss:
                return 'FAIL', f"{label}: {len(targets)} 件中 {miss} 件で欠落"
            if noparent == len(res):
                return 'SKIP', f"{label}: 親（任意）が不在のため問えない"
            if noparent:
                return 'PASS', f"{label}: 親が在る {len(res)-noparent} 件すべてで充足" \
                               f"（親不在 {noparent} 件は対象外）"
            return 'PASS', label

        if shape in ('single', 'envelope'):
            v, n = verdict_for([body], f"GET {path}")
            rows.append((d, v, n))
        elif shape == 'list':
            items = body.get('Resources', [])
            if not items:
                rows.append((d, 'ERROR', f"GET {path} が Resources を返さない")); continue
            v, n = verdict_for(items, f"GET {path}")
            rows.append((d, v, n))
    # 出力
    print(f"{'判定':<7}{'属性':<40}{'根拠':<26}備考")
    print('-' * 108)
    tally = {}
    for d, verdict, note in rows:
        tally[verdict] = tally.get(verdict, 0) + 1
        basis = f"RFC{d['rfc']} §{d['section']} L{d['start']}-{d['end']}"
        print(f"{verdict:<7}{d['attribute']:<40}{basis:<26}{note}")
    print('-' * 108)
    print('  '.join(f"{k} {v}" for k, v in sorted(tally.items())))
    return 1 if tally.get('FAIL') or tally.get('ERROR') else 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1], sys.argv[2]))
