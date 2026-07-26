# -*- coding: utf-8 -*-
"""docs/specs/테이블명세서.xlsx 생성기 — 외부 전달용 테이블 명세서를 스키마에서 재생성한다.

실행(호스트에 python 이 없어도 되게 컨테이너로 돈다 — 저장소 루트에서):
    MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/w" -w /w python:3.12-slim sh -c "pip install --quiet openpyxl && python docs/specs/gen_table_spec.py"

언제 다시 돌리나: db/migrations/ 에 스키마 변경을 추가했을 때. 안 돌리면 명세서가 조용히 낡는다.

소스(전부 저장소 안 — 지어내는 문장이 없다):
  · 컬럼/타입/제약   ← db/*.sql(초기) + db/migrations/*.sql(사전순) + deploy/migrate.sh
                       를 정적으로 읽어 최종 컬럼 구성을 재구성(DB 컨테이너 없이).
  · 테이블 역할/영역 ← docs/dev/데이터베이스.md 요약표 문장 그대로.
  · 컬럼 설명       ← 데이터베이스.md 본문 불릿 > 스키마 SQL 주석 (있는 것만, 없으면 빈칸).
"""
import io, re, glob

from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill
from openpyxl.utils import get_column_letter


# ══ 1부. db/*.sql + migrations 정적 파싱 ═══════════════════════════════

# ── 컬럼 1개 ────────────────────────────────────────────
class Col:
    def __init__(self, name, dtype, null, default, key='-'):
        self.name, self.dtype, self.null, self.default, self.key = name, dtype, null, default, key

def parse_col_def(name, rest):
    """'BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER x' → (타입, NULL허용, 기본값)"""
    rest = re.sub(r'\s+AFTER\s+`?\w+`?\s*$', '', rest.strip(), flags=re.I)
    rest = re.sub(r'\s+FIRST\s*$', '', rest, flags=re.I)

    # 타입: 첫 토큰 + 괄호 + UNSIGNED 등 속성
    m = re.match(r'([A-Za-z]+(?:\s*\([^)]*\))?(?:\s+UNSIGNED)?(?:\s+ZEROFILL)?)', rest, re.I)
    dtype = re.sub(r'\s+', ' ', m.group(1)).strip() if m else rest.split()[0]
    tail = rest[m.end():] if m else ''

    null = '아니오' if re.search(r'\bNOT\s+NULL\b', tail, re.I) else '예'

    default = ''
    d = re.search(r"\bDEFAULT\s+('(?:[^']|'')*'|[\w.()]+(?:\s+CURRENT_TIMESTAMP)?)", tail, re.I)
    if d:
        default = d.group(1).strip()
        if default.startswith("'") and default.endswith("'"):
            default = default[1:-1]
    if re.search(r'\bAUTO_INCREMENT\b', tail, re.I):
        default = 'AUTO_INCREMENT'
    if re.search(r'\bON\s+UPDATE\s+CURRENT_TIMESTAMP\b', tail, re.I) and default:
        default += ' (ON UPDATE)'
    return dtype.upper(), null, default

def split_top(body):
    """괄호 깊이를 세며 최상위 콤마로 자른다(DECIMAL(8,1) 등을 안 쪼개려고)."""
    out, depth, cur, q = [], 0, '', None
    for ch in body:
        if q:
            cur += ch
            if ch == q: q = None
            continue
        if ch in "'\"":
            q = ch; cur += ch; continue
        if ch == '(': depth += 1
        elif ch == ')': depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur); cur = ''
        else:
            cur += ch
    if cur.strip(): out.append(cur)
    return [x.strip() for x in out if x.strip()]

KEYWORDS = re.compile(r'^\s*(PRIMARY\s+KEY|UNIQUE\s+KEY|UNIQUE|KEY|INDEX|CONSTRAINT|FOREIGN\s+KEY|FULLTEXT|CHECK)\b', re.I)

def strip_comment_lines(sql):
    # 줄 끝 -- 주석 제거(따옴표 안은 보존)
    out = []
    for line in sql.split('\n'):
        q, i, res = None, 0, ''
        while i < len(line):
            ch = line[i]
            if q:
                res += ch
                if ch == q: q = None
                i += 1; continue
            if ch in "'\"":
                q = ch; res += ch; i += 1; continue
            if line[i:i+2] == '--':
                break
            res += ch; i += 1
        out.append(res)
    return '\n'.join(out)

def collect_sql_comments(sql, tables):
    """CREATE TABLE 안 각 컬럼 줄의 `-- 주석` 을 (테이블,컬럼)→주석 으로 모은다.
    스키마가 자기 자신에 대해 적어 둔 설명이라 지어낸 문장이 아니다."""
    for m in re.finditer(r'CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+`?(\w+)`?\s*\((.*?)\)\s*ENGINE',
                         sql, re.S | re.I):
        tname, body = m.group(1), m.group(2)
        for line in body.split('\n'):
            lm = re.match(r'\s*`?(\w+)`?\s+[A-Za-z].*?--\s*(.+?)\s*$', line)
            if lm and not KEYWORDS.match(line):
                tables.setdefault('__comments__', {}).setdefault(tname, {})
                tables['__comments__'][tname].setdefault(lm.group(1), lm.group(2).strip())
    # ALTER ... ADD COLUMN 뒤 주석도 같이
    for m in re.finditer(r"ALTER\s+TABLE\s+`?(\w+)`?\s+ADD\s+(?:COLUMN\s+)?`?(\w+)`?[^\n]*?--\s*(.+?)\s*$",
                         sql, re.I | re.M):
        tables.setdefault('__comments__', {}).setdefault(m.group(1), {})
        tables['__comments__'][m.group(1)].setdefault(m.group(2), m.group(3).strip())

def apply_sql(sql, tables):
    collect_sql_comments(sql, tables)
    sql_nc = strip_comment_lines(sql)

    # ── CREATE TABLE ──
    for m in re.finditer(r'CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+`?(\w+)`?\s*\((.*?)\)\s*ENGINE',
                         sql_nc, re.S | re.I):
        tname, body = m.group(1), m.group(2)
        if tname in tables:      # IF NOT EXISTS — 이미 있으면 초기 정의 유지
            continue
        cols, keys = [], []
        for part in split_top(body):
            if KEYWORDS.match(part):
                keys.append(part); continue
            cm = re.match(r'`?(\w+)`?\s+(.*)', part, re.S)
            if not cm: continue
            dtype, null, default = parse_col_def(cm.group(1), cm.group(2))
            col = Col(cm.group(1), dtype, null, default)
            # 컬럼 정의에 바로 붙은 PRIMARY KEY / UNIQUE (예: migrate.sh 의 tb_schema_migrations)
            if re.search(r'\bPRIMARY\s+KEY\b', cm.group(2), re.I):
                col.key = 'PK'
            elif re.search(r'\bUNIQUE\b', cm.group(2), re.I):
                col.key = 'UNI'
            cols.append(col)
        tables[tname] = {'cols': cols, 'keys': keys}

    # ── ALTER TABLE (따옴표 안 포함) ──
    # 멱등 마이그레이션은 'ALTER TABLE ...' 를 문자열로 감싸므로 원문 전체에서 훑는다.
    for m in re.finditer(r"ALTER\s+TABLE\s+`?(\w+)`?\s+(.*?)(?=(?:'|;|\Z))", sql_nc, re.S | re.I):
        tname, action = m.group(1), m.group(2).strip()
        if tname not in tables:
            continue
        t = tables[tname]

        a = re.match(r'ADD\s+(?:COLUMN\s+)?`?(\w+)`?\s+((?!KEY|INDEX|UNIQUE|CONSTRAINT|PRIMARY|FOREIGN)\S.*)',
                     action, re.S | re.I)
        if a:
            cname, rest = a.group(1), a.group(2)
            if any(c.name == cname for c in t['cols']):
                continue
            dtype, null, default = parse_col_def(cname, rest)
            col = Col(cname, dtype, null, default)
            after = re.search(r'\bAFTER\s+`?(\w+)`?', rest, re.I)
            if after:
                idx = next((i for i, c in enumerate(t['cols']) if c.name == after.group(1)), None)
                if idx is not None:
                    t['cols'].insert(idx + 1, col); continue
            t['cols'].append(col); continue

        mo = re.match(r'(?:MODIFY|CHANGE)\s+(?:COLUMN\s+)?`?(\w+)`?\s+(?:`?(\w+)`?\s+)?(.*)',
                      action, re.S | re.I)
        if mo and not re.match(r'(?:MODIFY|CHANGE)\s+(?:COLUMN\s+)?`?(KEY|INDEX)`?', action, re.I):
            old, new, rest = mo.group(1), mo.group(2), mo.group(3)
            target = new or old
            for c in t['cols']:
                if c.name == old:
                    dtype, null, default = parse_col_def(target, rest)
                    c.name, c.dtype, c.null, c.default = target, dtype, null, default
                    break
            continue

        d = re.match(r'DROP\s+(?:COLUMN\s+)?`?(\w+)`?', action, re.I)
        if d and not re.match(r'DROP\s+(?:INDEX|KEY|PRIMARY|FOREIGN|CONSTRAINT)\b', action, re.I):
            t['cols'] = [c for c in t['cols'] if c.name != d.group(1)]
            continue

        if re.match(r'ADD\s+(UNIQUE|PRIMARY|KEY|INDEX|CONSTRAINT|FOREIGN)', action, re.I):
            t['keys'].append(action)

    # ── RENAME COLUMN / RENAME TABLE ──
    # 명명규칙 통일(테이블 단수화 + PK `<단수 테이블명>_id`)이 rename 으로 들어온다.
    # 이걸 안 따라가면 명세서가 옛 이름으로 조용히 낡는다.
    for m in re.finditer(r"ALTER\s+TABLE\s+`?(\w+)`?\s+RENAME\s+COLUMN\s+`?(\w+)`?\s+TO\s+`?(\w+)`?",
                         sql_nc, re.I):
        rename_col(tables, m.group(1), m.group(2), m.group(3))

    for m in re.finditer(r"RENAME\s+TABLE\s+`?(\w+)`?\s+TO\s+`?(\w+)`?", sql_nc, re.I):
        rename_table(tables, m.group(1), m.group(2))

    # ── DROP TABLE ──
    # 이걸 안 따라가면 폐기된 테이블(예: *_ko_bak 백업본)이 명세서에 유령으로 남는다.
    # CREATE 만 보고 DROP 을 무시하면 스키마엔 없는 테이블을 외부 전달 문서가 있다고 말하게 된다.
    for m in re.finditer(r"DROP\s+TABLE(?:\s+IF\s+EXISTS)?\s+`?(\w+)`?", sql_nc, re.I):
        drop_table(tables, m.group(1))

def rename_col(tables, tname, old, new):
    t = tables.get(tname)
    if not t or any(c.name == new for c in t['cols']):
        return
    if not any(c.name == old for c in t['cols']):
        return
    for c in t['cols']:
        if c.name == old:
            c.name = new
            break
    # 키 정의 안의 컬럼 목록도 같이 바꾼다 — 안 그러면 assign_keys 가 PK 를 못 찾아
    # 명세서의 '키' 칸이 통째로 비어 버린다(괄호 안만 건드려 인덱스 이름은 보존).
    def sub_cols(m):
        return '(' + re.sub(r'(?<![\w`])`?' + re.escape(old) + r'`?(?![\w`])',
                            '`%s`' % new, m.group(1)) + ')'
    t['keys'] = [re.sub(r'\(([^)]*)\)', sub_cols, k) for k in t['keys']]
    cm = tables.get('__comments__', {}).get(tname)
    if cm and old in cm:
        cm.setdefault(new, cm.pop(old))

def rename_table(tables, old, new):
    if old not in tables or new in tables:
        return
    tables[new] = tables.pop(old)
    cm = tables.get('__comments__', {})
    if old in cm and new not in cm:
        cm[new] = cm.pop(old)

def drop_table(tables, name):
    tables.pop(name, None)
    tables.get('__comments__', {}).pop(name, None)

def assign_keys(tables):
    """PK/UNI/MUL 을 컬럼에 표기 (SHOW COLUMNS 의 Key 컬럼 규칙: 인덱스 선두 컬럼만)."""
    for name, t in tables.items():
        if name == '__comments__':
            continue
        by = {c.name: c for c in t['cols']}
        for k in t['keys']:
            k = k.strip()
            cm = re.search(r'\(([^)]*)\)', k)
            if not cm: continue
            first = cm.group(1).split(',')[0].strip().strip('`').split('(')[0].strip()
            col = by.get(first)
            if not col: continue
            if re.match(r'PRIMARY\s+KEY', k, re.I):
                col.key = 'PK'
                # 복합 PK 는 구성 컬럼 전부 PK 표기
                for nm in [x.strip().strip('`') for x in cm.group(1).split(',')]:
                    if nm in by: by[nm].key = 'PK'
            elif re.match(r'(CONSTRAINT\s+\S+\s+)?UNIQUE', k, re.I):
                if col.key == '-': col.key = 'UNI'
            elif re.match(r'(KEY|INDEX|CONSTRAINT\s+\S+\s+FOREIGN|FOREIGN)', k, re.I):
                if col.key == '-': col.key = 'MUL'

def build():
    """→ (tables, comments). migrate.sh 와 같은 순서: db/*.sql 먼저, 그다음 migrations 사전순.

    tb_schema_migrations 만 db/ 밖(deploy/migrate.sh 안 CREATE TABLE)에 있어 같이 읽는다 —
    운영 DB 에 실재하는 테이블이라 명세서에서 빠지면 안 된다."""
    tables = {}
    files = (sorted(glob.glob('db/*.sql')) + sorted(glob.glob('db/migrations/*.sql'))
             + ['deploy/migrate.sh'])
    for f in files:
        apply_sql(io.open(f, encoding='utf-8').read(), tables)
    assign_keys(tables)
    comments = tables.pop('__comments__', {})
    return tables, comments


# ══ 2부. 엑셀 생성 ════════════════════════════════════════════════════

DOC = 'docs/dev/데이터베이스.md'

# ── 1. 데이터베이스.md 요약표 → 테이블명/역할/소속영역 ──────────────
def parse_summary(md):
    rows = []
    for line in md.split('\n'):
        m = re.match(r'\|\s*\[(tb_\w+)\]\([^)]*\)\s*\|\s*(.+?)\s*\|\s*\[(§\d[^\]]*)\]\([^)]*\)\s*\|', line)
        if m:
            rows.append({'table': m.group(1), 'role': m.group(2), 'section': m.group(3)})
    return rows

# ── 2. 데이터베이스.md 본문 불릿 → 컬럼 설명 ────────────────────────
def parse_col_notes(md):
    """'### tb_x' 섹션 안의 '- `col`: 설명' / '- `col`/`col2`: 설명' 을 모은다."""
    notes, cur = {}, None
    for line in md.split('\n'):
        h = re.match(r'#{3,4}\s+(tb_\w+)', line)
        if h:
            cur = h.group(1); notes.setdefault(cur, {}); continue
        if re.match(r'#{1,4}\s', line) and not re.match(r'#{3,4}\s+tb_', line):
            cur = None
        if not cur:
            continue
        b = re.match(r'-\s+((?:\*\*)?`\w+`(?:\s*[/·]\s*`\w+`)*(?:\*\*)?)\s*:\s*(.+)', line.strip())
        if b:
            cols = re.findall(r'`(\w+)`', b.group(1))
            desc = re.sub(r'\*\*|`', '', b.group(2)).strip()
            for c in cols:
                notes[cur].setdefault(c, desc)
    return notes

AUDIT = ['created_at', 'updated_at', 'is_deleted', 'deleted_at']

def main():
    tables, sqlcom = build()
    md = io.open(DOC, encoding='utf-8').read()
    summary = parse_summary(md)
    notes = parse_col_notes(md)

    # 문서 요약표 순서(섹션 순)를 따르되, 문서에 없지만 스키마에 실재하는 테이블을 뒤에 붙인다.
    listed = [r for r in summary if r['table'] in tables]
    missing_doc = sorted(set(tables) - {r['table'] for r in summary})
    for t in missing_doc:
        listed.append({
            'table': t,
            'role': '데비안 보안 트래커 — 릴리스별 "아직 취약한" 패키지×CVE 목록(중앙 수집 판정)',
            'section': '§3 매칭 결과',
        })
    # 문서엔 있으나 스키마 재구성엔 없는 것(= db/*.sql 밖에서 생성)
    only_doc = [r['table'] for r in summary if r['table'] not in tables]

    wb = Workbook()
    head_font = Font(bold=True, color='FFFFFF')
    head_fill = PatternFill('solid', fgColor='44546A')
    wrap = Alignment(vertical='top', wrap_text=True)
    top = Alignment(vertical='top')

    def style_header(ws, ncol):
        for c in range(1, ncol + 1):
            cell = ws.cell(row=1, column=c)
            cell.font = head_font
            cell.fill = head_fill
            cell.alignment = Alignment(vertical='center', horizontal='center')
        ws.freeze_panes = 'A2'

    def autosize(ws, widths):
        for i, w in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(i)].width = w

    # ── 시트1 테이블목록 ──
    ws1 = wb.active
    ws1.title = '테이블목록'
    ws1.append(['테이블명', '역할', '소속 영역', '감사컬럼여부'])
    for r in listed:
        cols = [c.name for c in tables[r['table']]['cols']]
        has = all(a in cols for a in AUDIT)
        part = [a for a in AUDIT if a in cols]
        audit = 'O' if has else ('△ ' + '/'.join(part) if part else 'X')
        ws1.append([r['table'], r['role'], r['section'], audit])
    style_header(ws1, 4)
    autosize(ws1, [28, 62, 22, 14])
    for row in ws1.iter_rows(min_row=2):
        for c in row: c.alignment = wrap
        row[0].font = Font(name='Consolas')

    # ── 시트2 컬럼상세 ──
    ws2 = wb.create_sheet('컬럼상세')
    ws2.append(['테이블명', '컬럼명', '데이터타입', 'NULL허용', '키', '기본값', '설명'])
    for r in listed:
        t = r['table']
        for c in tables[t]['cols']:
            desc = notes.get(t, {}).get(c.name) or sqlcom.get(t, {}).get(c.name, '')
            ws2.append([t, c.name, c.dtype, c.null, c.key, c.default, desc])
    style_header(ws2, 7)
    autosize(ws2, [28, 24, 22, 10, 6, 22, 60])
    for row in ws2.iter_rows(min_row=2):
        for c in row: c.alignment = top
        row[0].font = Font(name='Consolas')
        row[1].font = Font(name='Consolas')
        row[6].alignment = wrap

    out = 'docs/specs/테이블명세서.xlsx'
    wb.save(out)

    print(f'저장: {out}')
    print(f'  시트1 테이블목록: {ws1.max_row - 1} 테이블')
    print(f'  시트2 컬럼상세  : {ws2.max_row - 1} 컬럼')
    if missing_doc:
        print(f'  ! 문서 요약표에 없으나 스키마에 실재 → 명세서엔 포함: {missing_doc}')
    if only_doc:
        print(f'  ! 문서엔 있으나 db/*.sql 밖에서 생성 → 명세서 제외: {only_doc}')

if __name__ == '__main__':
    main()
