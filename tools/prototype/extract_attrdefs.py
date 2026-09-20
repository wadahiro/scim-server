#!/usr/bin/env python3
"""層 A-1: 属性定義エントリを抽出し、必須メンバ検査の候補を生成する。

RFC 7643/7644 は属性定義に 2 つの体裁を使う:
  体裁A   "   name"              名前だけの行、説明は 6 スペース字下げの続き
  体裁B   "   name  Description" 名前と説明が同一行
入れ子のサブ属性は字下げが深い（"      supported  ..."）ので親を追跡する。

cardinality は無条件と条件付き（"REQUIRED if ...", "REQUIRED when ..."）があり、
取り違えると誤検出になるので必ず分離する。出力の行番号は生 RFC の行番号。
"""
import re, json, sys
from collections import Counter
from pathlib import Path

CARD = re.compile(r'\b(REQUIRED|OPTIONAL|RECOMMENDED)\b')
FURN = re.compile(r'^(RFC \d+\s|Hunt,|.*\[Page \d+\]\s*$)')
HEAD = re.compile(r'^(\d+(?:\.\d+)*)\.\s+(\S.*)$')
NAME = r'[A-Za-z][A-Za-z0-9_$]*'
# 見出し行: 字下げ + 名前 [+ 2スペース以上 + 説明]
DEF  = re.compile(rf'^( +)({NAME})(?:  +(\S.*))?$')

def sections(lines):
    out = []
    for i, ln in enumerate(lines):
        m = HEAD.match(ln.rstrip())
        if m and not ln.startswith(' '):
            out.append((i + 1, m.group(1), m.group(2)))
    return out

def sec_at(secs, n):
    cur = ('0', '')
    for ln, s, t in secs:
        if ln <= n: cur = (s, t)
        else: break
    return cur

def extract(rfc, path):
    raw = Path(path).read_text(encoding='utf-8', errors='replace').split('\n')
    secs = sections(raw)
    body = [(i + 1, ln.replace('\f', '').rstrip())
            for i, ln in enumerate(raw)
            if not FURN.match(ln.replace('\f', '').strip()) and '\f' not in ln]

    out = []
    stack = []            # [(indent, name)] 親の入れ子
    i = 0
    while i < len(body):
        lineno, ln = body[i]
        m = DEF.match(ln)
        if not m:
            i += 1; continue
        indent, name, inline = len(m.group(1)), m.group(2), m.group(3)
        # 属性定義は 3 スペース単位の字下げ（3, 6, 9）だけを見る
        if indent not in (3, 6, 9):
            i += 1; continue
        # 説明本文を集める: 見出しより深い字下げの行
        buf = [inline] if inline else []
        end = lineno
        j = i + 1
        while j < len(body):
            n2, l2 = body[j]
            if l2.strip() == '':
                # 空行1つ挟んで更に深い継続があれば続き（ページ境界対策）
                if (j + 1 < len(body) and body[j + 1][1].strip()
                        and len(body[j + 1][1]) - len(body[j + 1][1].lstrip()) > indent
                        and not DEF.match(body[j + 1][1])):
                    j += 1; continue
                break
            ind2 = len(l2) - len(l2.lstrip())
            if ind2 <= indent: break
            if DEF.match(l2) and ind2 in (6, 9): break   # 次のサブ属性
            buf.append(l2.strip()); end = n2; j += 1
        text = re.sub(r'\s+', ' ', ' '.join(buf)).strip()
        if not text or len(text) < 12:
            i = max(j, i + 1); continue
        cm = CARD.search(text)
        if cm:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1] if stack else None
            tail = text[cm.end():].strip()
            cond = bool(re.match(r'^(if|when|unless)\b', tail, re.I))
            sec, title = sec_at(secs, lineno)
            out.append({
                'rfc': rfc, 'section': sec, 'section_title': title,
                'start': lineno, 'end': end,
                'attribute': f'{parent}.{name}' if parent else name,
                'parent': parent, 'name': name,
                'cardinality': cm.group(1),
                'conditional': cond,
                'condition': tail.rstrip('.') if cond else None,
                'text': text,
            })
        stack.append((indent, name))
        i = max(j, i + 1)
    return out

if __name__ == '__main__':
    base = Path(sys.argv[1]); allo = []
    for rfc in (7643, 7644):
        allo += extract(rfc, base / f'rfc{rfc}.txt')
    json.dump(allo, open(sys.argv[2], 'w'), ensure_ascii=False, indent=1)
    print(f"属性定義エントリ: {len(allo)} 件")
    print("  cardinality:", dict(Counter(a['cardinality'] for a in allo)))
    print("  無条件:", sum(1 for a in allo if not a['conditional']),
          "/ 条件付き:", sum(1 for a in allo if a['conditional']))
    print("\n  節ごと:")
    for (r, s, t), n in sorted(Counter((a['rfc'], a['section'], a['section_title'])
                                       for a in allo).items()):
        print(f"    RFC{r} §{s:<8} {t[:42]:<44} {n:>3}")
