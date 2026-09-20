#!/usr/bin/env python3
"""spec から準拠ケース候補を機械抽出する。

生の RFC txt を入力にし、出力の行番号はすべて生ファイルの行番号。
"""
import hashlib, re, json, sys
from pathlib import Path

KW10 = re.compile(r'\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|'
                  r'RECOMMENDED|REQUIRED|OPTIONAL|MAY)\b')
KW7  = re.compile(r'\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|MAY)\b')
CARD = re.compile(r'\b(REQUIRED|OPTIONAL|RECOMMENDED)\b')

FURNITURE = re.compile(r'^(RFC \d+\s|Hunt,|.*\[Page \d+\]\s*$)')
HEADING   = re.compile(r'^(\d+(?:\.\d+)*)\.\s+(\S.*)$')
FIGCAP    = re.compile(r'^\s+(Figure|Table) \d+[:.]')
ABNF      = re.compile(r'^\s{2,}[A-Za-z][A-Za-z0-9-]*\s*=\s')
TABLEROW  = re.compile(r'^\s*[|+]')
# 属性定義エントリ:  "   name  Description ... REQUIRED."
ATTRDEF   = re.compile(r'^\s{3,6}([a-zA-Z][a-zA-Z0-9_$.]*)\s{2,}(\S.*)$')
OUTCOME   = re.compile(r'\b(fails?|returns?|is (ignored|applied|replaced|equivalent|assumed)|'
                       r'are applied|status code|treated as|considered|SHALL be|'
                       r'responds?|rejects?)\b', re.I)

def load(path):
    return Path(path).read_text(encoding='utf-8', errors='replace').split('\n')

def segment(lines):
    """生の行から論理ブロックを作る。各ブロックは生ファイルの行範囲を持つ。

    ページ装飾（ヘッダ・フッタ・改ページ）は落とすが、その跡の空行だけで
    段落を切らない（PP-1）。直前が文末記号で終わらず直後が小文字で続くなら結合する。
    """
    # 1) 装飾行に印を付ける
    keep = []
    for i, ln in enumerate(lines):
        s = ln.replace('\f', '').rstrip()
        if FURNITURE.match(s.strip()) or '\f' in ln:
            continue
        keep.append((i + 1, s))          # (生の行番号, 本文)

    # 2) 空行でブロック化
    blocks, cur, start = [], [], None
    for lineno, s in keep:
        if s.strip() == '':
            if cur:
                blocks.append([start, cur[-1][0], [t for _, t in cur]])
                cur, start = [], None
        else:
            if start is None:
                start = lineno
            cur.append((lineno, s))
    if cur:
        blocks.append([start, cur[-1][0], [t for _, t in cur]])

    # 3) PP-1: ページ境界で割れた段落を結合する
    merged = []
    for b in blocks:
        if merged:
            prev = merged[-1]
            ptext = prev[2][-1].rstrip()
            ntext = b[2][0]
            if (not re.search(r'[.:;?!]$', ptext) and len(ptext) > 50
                    and re.match(r'^ {3}[a-z)\'"]', ntext)
                    and not re.match(r'^ {3}o\s', ntext)):
                prev[1] = b[1]
                prev[2].extend(b[2])
                continue
        merged.append(b)
    return merged

def classify(block):
    start, end, body = block
    first = body[0]
    flat = re.sub(r'\s+', ' ', ' '.join(body)).strip()
    if HEADING.match(first.strip()) and len(body) <= 2 and len(flat) < 90:
        return 'heading', flat
    if FIGCAP.match(first):
        return 'caption', flat
    tbl = sum(1 for l in body if TABLEROW.match(l))
    if tbl and tbl >= len(body) * 0.5:
        return 'table', flat
    st = first.strip()
    if st.startswith('{') or st.startswith('[') or st.startswith('"'):
        return 'json', flat
    if sum(1 for l in body if ABNF.match(l)) >= max(1, len(body) * 0.5):
        return 'abnf', flat
    if re.match(r'^\s*(GET|POST|PUT|PATCH|DELETE|HTTP/1\.1) ', first):
        return 'http_example', flat
    return 'prose', flat

def section_index(lines):
    """生の行番号 -> 節番号 の対応表。"""
    marks = []
    for i, ln in enumerate(lines):
        m = HEADING.match(ln.rstrip())
        if m and not ln.startswith(' '):
            marks.append((i + 1, m.group(1)))
    return marks

def sec_of(marks, lineno):
    cur = '0'
    for ln, sec in marks:
        if ln <= lineno:
            cur = sec
        else:
            break
    return cur

def text_sha256(text):
    """空白正規化（連続する空白を 1 個に畳み、前後を trim）した本文の sha256。"""
    normalized = re.sub(r'\s+', ' ', text).strip()
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

def extract(rfc, path, no_text=False):
    lines = load(path)
    marks = section_index(lines)
    out = []
    for b in segment(lines):
        kind, flat = classify(b)
        start, end, body = b
        kws = sorted(set(KW10.findall(flat)))
        entry = {
            'rfc': rfc, 'section': sec_of(marks, start),
            'start': start, 'end': end, 'kind': kind,
            'keywords': kws,
            'kw7': bool(KW7.search(flat)),
            'cardinality_only': bool(kws) and not KW7.search(flat),
        }
        if no_text:
            entry['text_sha256'] = text_sha256(flat)
        else:
            entry['text'] = flat
        # 分類
        if kind in ('json', 'abnf', 'http_example'):
            entry['class'] = 'example'
        elif kind in ('heading', 'caption'):
            entry['class'] = 'meta'
        elif kind == 'table':
            entry['class'] = 'table'
        elif kws:
            entry['class'] = 'definitional'
        elif OUTCOME.search(flat):
            entry['class'] = 'definitional_prose'     # ★ 平文の要件候補
        else:
            entry['class'] = 'explanatory'
        # A-1: 属性定義エントリ
        m = ATTRDEF.match(body[0])
        if m and CARD.search(flat):
            entry['attr_def'] = {'name': m.group(1),
                                 'cardinality': CARD.search(flat).group(1)}
        out.append(entry)
    return out

if __name__ == '__main__':
    argv = sys.argv[1:]
    no_text = '--no-text' in argv
    if no_text:
        argv = [a for a in argv if a != '--no-text']
    base = Path(argv[0])
    allout = {}
    for rfc in (7643, 7644):
        allout[rfc] = extract(rfc, base / f'rfc{rfc}.txt', no_text=no_text)
    json.dump(allout, open(argv[1], 'w'), ensure_ascii=False, indent=1)
    for rfc, rows in allout.items():
        from collections import Counter
        c = Counter(r['class'] for r in rows)
        print(f"RFC {rfc}: ブロック {len(rows)}  {dict(c)}")
        print(f"   属性定義エントリ: {sum(1 for r in rows if 'attr_def' in r)}")
        print(f"   cardinality のみ(REQUIRED/OPTIONAL/RECOMMENDED だけ): "
              f"{sum(1 for r in rows if r['cardinality_only'])}")
