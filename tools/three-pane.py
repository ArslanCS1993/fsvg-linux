#!/usr/bin/env python3
"""
three-pane.py -- FSVG flowchart  |  assembly  |  original Linux source

Reads a real instruction trace, the real kernel source, and an FSVG flowchart of
the same code, and emits one self-contained HTML page where clicking anything in
one pane highlights it in the other two.

    python3 three-pane.py \
        --trace /path/to/trace.json \
        --kernel /path/to/linux-source-6.8.0 \
        --entry arch/x86/entry/entry_64.S \
        --out kernel/arch/x86/entry/entry_SYSCALL_64.html
"""
import argparse, html, json, os, re, sys

# Fallbacks for this box; override with --trace/--kernel.
DEF_TRACE = '/root/gh-cpu3d/src/trace.json'
DEF_KERNEL = '/tmp/ksrc64/linux-source-6.8.0'
DEF_ENTRY = 'arch/x86/entry/entry_64.S'

# ---------------------------------------------------------------- the FSVG
# Hand-written flowchart of entry_SYSCALL_64. `src` is the entry_64.S line it
# implements, `need` is the fsvgc ops it uses ('A+B' for several, empty for a
# shape that expands to none). Whether those ops EXIST is not asserted here --
# it is looked up in fsvgc at build time, because a hand-written claim about
# what the language cannot do goes stale the moment the language learns it.
FLOW = [
    ('entry',   'rect',   'SWAPGS',                                   91,  'SWAPGS'),
    ('tss2',    'rect',   'MOV @TSS_SP2, RSP',                        93,  'MOV'),
    ('kcr3',    'rect',   'SWITCH_TO_KERNEL_CR3',                     94,  None),
    ('topstack','rect',   'MOV RSP, @PCPU_TOP_OF_STACK',              95,  'MOV'),
    ('p_ss',    'rect',   'PUSH USER_DS',                            101,  'PUSH'),
    ('p_sp',    'rect',   'PUSH @TSS_SP2',                           102,  'PUSH'),
    ('p_fl',    'rect',   'PUSH R11',                                103,  'PUSH'),
    ('p_cs',    'rect',   'PUSH USER_CS',                            104,  'PUSH'),
    ('p_ip',    'rect',   'PUSH RCX',                                105,  'PUSH'),
    ('p_ax',    'rect',   'PUSH RAX',                                107,  'PUSH'),
    # PUSH_AND_CLEAR_REGS is modelled as the pushes plus the zeroing, and fsvgc
    # has all of those. The old value named 'CLEAR', an op that never existed as
    # an opcode -- which is exactly why the page reported a deficit forever.
    ('clear',   'rect',   'PUSH_AND_CLEAR_REGS RAX=-ENOSYS',         109,  'PUSH+XOR'),
    ('arg0',    'rect',   'MOV RDI, RSP',                            112,  'MOV'),
    ('arg1',    'rect',   'MOVSXD RSI, EAX',                         114,  'MOVSXD'),
    ('call',    'rect',   'CALL do_syscall_64',                      121,  'CALL'),
    ('xen',     'poly',   'Xen PV?',                                 130,  None),
    ('sysret',  'rect',   'POP_REGS  ->  SYSRET',                    139,  'POP+SYSRET'),
    ('iret',    'rect',   'swapgs_restore_regs_and_return',          152,  None),
]

EDGES = [
    ('entry','tss2'), ('tss2','kcr3'), ('kcr3','topstack'), ('topstack','p_ss'),
    ('p_ss','p_sp'), ('p_sp','p_fl'), ('p_fl','p_cs'), ('p_cs','p_ip'),
    ('p_ip','p_ax'), ('p_ax','clear'), ('clear','arg0'), ('arg0','arg1'),
    ('arg1','call'), ('call','xen'),
    ('xen','sysret','yes'), ('xen','iret','no'),
]

def layout():
    """Straight-line column, test near the bottom."""
    W, H, GAP = 300, 40, 14
    pos = {}
    y = 30
    for i, (sid, kind, *_rest) in enumerate(FLOW):
        h = 62 if kind == 'poly' else H
        pos[sid] = (40, y, W, h)
        y += h + GAP
    return pos, max(y + 30, 720)

def build_svg():
    pos, height = layout()
    P = ['<svg id="flow" viewBox="0 0 380 %d" xmlns="http://www.w3.org/2000/svg">' % height]
    for a, b, *_ in EDGES:
        ax, ay, aw, ah = pos[a]
        bx, by, bw, bh = pos[b]
        x1, y1 = ax + aw / 2, ay + ah
        x2, y2 = bx + bw / 2, by
        if abs(x1 - x2) < 1:
            P.append('<path class="edge" data-a="%s" data-b="%s" d="M%.1f %.1f L%.1f %.1f"/>'
                     % (a, b, x1, y1, x2, y2))
        else:
            my = (y1 + y2) / 2
            P.append('<path class="edge" data-a="%s" data-b="%s" d="M%.1f %.1f V%.1f H%.1f V%.1f"/>'
                     % (a, b, x1, y1, my, x2, my, y2))
    for sid, kind, label, line, need in FLOW:
        x, y, w, h = pos[sid]
        cls = 'node' + (' test' if kind == 'poly' else '')
        P.append('<g class="%s" id="n-%s" data-line="%d" data-need="%s">' % (cls, sid, line, need or ''))
        if kind == 'poly':
            cx, cy = x + w / 2, y + h / 2
            P.append('<polygon points="%.1f,%.1f %.1f,%.1f %.1f,%.1f %.1f,%.1f"/>'
                     % (cx, y, x + w, cy, cx, y + h, x, cy))
        else:
            P.append('<rect x="%d" y="%d" width="%d" height="%d" rx="4"/>' % (x, y, w, h))
        P.append('<text x="%.1f" y="%.1f">%s</text>' % (x + w / 2, y + h / 2 + 4, html.escape(label)))
        P.append('<text class="meta" x="%.1f" y="%.1f">%s:%d</text>' % (x + w / 2, y + h - 5, 'entry_64.S', line))
        P.append('</g>')
    P.append('</svg>')
    return ''.join(P)

# ---------------------------------------------------------------- assembly
def load_asm(trace, limit):
    d = json.load(open(trace))
    pat = re.compile(r'([0-9a-f]+)\s+<([^>]+)>:\s*(.*)$')
    rows = []
    for x in d['steps']:
        if not x['file'].endswith('arch/x86/entry/entry_64.S'):
            continue
        m = pat.search(x['insn'])
        rows.append((x['line'], m.group(1), m.group(3).strip()))
    return rows[:limit] if limit else rows

def build_asm_rows(rows):
    out, prev = [], None
    for line, addr, text in rows:
        cls = ' same' if line == prev else ' new'
        out.append('<div class="a%s" data-line="%d"><span class="ad">%s</span>'
                   '<span class="at">%s</span></div>' % (cls, line, addr, html.escape(text)))
        prev = line
    return ''.join(out)

def build_src(kernel, entry, lo, hi, keep):
    lines = open(os.path.join(kernel, entry)).read().split('\n')
    out = []
    for n in range(lo, hi):
        if n > len(lines):
            break
        s = lines[n - 1].rstrip()
        hit = ' hit' if n in keep else ''
        out.append('<div class="c%s" data-line="%d"><span class="ln">%4d</span>%s</div>'
                   % (hit, n, n, html.escape(s) or ' '))
    return ''.join(out)

CSS = """
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#c9d1d9;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace}
header{display:flex;gap:14px;align-items:baseline;padding:10px 14px;border-bottom:1px solid #21262d;
  position:sticky;top:0;background:#0d1117;z-index:5}
h1{font-size:14px;margin:0;color:#58a6ff;font-weight:600}
header span{color:#8b949e;font-size:12px}
header b{color:#3fb950;font-weight:600}
main{display:grid;grid-template-columns:380px 1fr 1fr;height:calc(100vh - 43px)}
pane{overflow:auto;border-right:1px solid #21262d}
h2{position:sticky;top:0;margin:0;padding:6px 10px;background:#161b22;color:#8b949e;
  font-size:11px;letter-spacing:.09em;text-transform:uppercase;border-bottom:1px solid #21262d;z-index:4}
/* flow */
.node rect,.node polygon{fill:#161b22;stroke:#30363d;stroke-width:1.5}
.node.test polygon{fill:#1c2128;stroke:#d29922}
.node text{fill:#e6edf3;font-size:11px;text-anchor:middle;pointer-events:none}
.node .meta{fill:#6e7681;font-size:9px}
.node{cursor:pointer}
.edge{stroke:#30363d;stroke-width:1.5;fill:none}
.node.on rect,.node.on polygon{stroke:#3fb950;fill:#12261a}
.node.miss rect,.node.miss polygon{stroke:#f85149;stroke-dasharray:3 3}
.node.on text{fill:#7ee787}
/* asm */
.a{display:flex;gap:10px;padding:1px 10px;white-space:pre}
.a.new{border-top:1px solid #21262d;margin-top:2px}
.ad{color:#484f58;flex:0 0 110px}
.at{color:#c9d1d9}
.a.on{background:#12261a}
.a.on .at{color:#7ee787}
/* src */
.c{padding:0 10px;white-space:pre}
.ln{color:#484f58;display:inline-block;width:44px}
.c.hit{background:#12261a}
.c.hit .ln{color:#3fb950}
.c.on{background:#1f3d5c}
.legend{padding:6px 10px;color:#6e7681;font-size:11px;border-top:1px solid #21262d}
.k{display:inline-block;padding:0 5px;border-radius:3px;background:#1f6feb22;color:#58a6ff;margin:1px}
"""

JS = """
const flow=document.getElementById('flow');
function clear(){document.querySelectorAll('.on').forEach(e=>e.classList.remove('on'));
  flow.querySelectorAll('.edge').forEach(e=>e.style.stroke='');}
function hl(line){
  clear();
  const n=flow.querySelector(`[data-line="${line}"]`);
  if(n){n.classList.add('on');
    flow.querySelectorAll(`.edge[data-a="${n.id.slice(2)}"],.edge[data-b="${n.id.slice(2)}"]`)
        .forEach(e=>e.style.stroke='#3fb950');}
  document.querySelectorAll(`.a[data-line="${line}"]`).forEach(e=>e.classList.add('on'));
  const c=document.querySelector(`.c[data-line="${line}"]`);
  if(c){c.classList.add('on');c.scrollIntoView({block:'center'});}
}
// flow box -> everything
flow.querySelectorAll('.node').forEach(n=>n.addEventListener('click',()=>hl(n.dataset.line)));
// asm -> everything
document.querySelectorAll('.a').forEach(a=>a.addEventListener('click',()=>hl(a.dataset.line)));
// source -> everything
document.querySelectorAll('.c').forEach(c=>c.addEventListener('click',()=>hl(c.dataset.line)));
document.addEventListener('keydown',e=>{if(e.key==='Escape')clear();});
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='kernel/arch/x86/entry/entry_SYSCALL_64.html')
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--title', default='entry_SYSCALL_64')
    ap.add_argument('--trace', default=DEF_TRACE,
                    help='trace.json from the cpu-3d viewer')
    ap.add_argument('--kernel', default=DEF_KERNEL,
                    help='unpacked linux-source tree')
    ap.add_argument('--entry', default=DEF_ENTRY,
                    help='kernel-relative path of the file being translated')
    ap.add_argument('--from', dest='lo', type=int, default=60,
                    help='first source line to show in pane 3')
    ap.add_argument('--to', dest='hi', type=int, default=157,
                    help='last source line to show in pane 3')
    a = ap.parse_args()

    for p, what in ((a.trace, 'trace'), (a.kernel, 'kernel tree')):
        if not os.path.exists(p):
            ap.error('%s not found: %s' % (what, p))
    if not os.path.exists(os.path.join(a.kernel, a.entry)):
        ap.error('entry file not found: %s/%s' % (a.kernel, a.entry))

    rows = load_asm(a.trace, a.limit)
    keep = set(r[0] for r in rows)

    # What does the language still lack? ASK THE COMPILER.
    #
    # This used to be a hardcoded count of shapes whose `need` was non-empty, so
    # the page went on saying "N shapes need ops fsvgc lacks" long after those
    # ops were implemented -- a live page asserting a deficit that no longer
    # existed. Deriving it from fsvgc's own op table means the claim cannot
    # outlive the fact.
    sys.path.insert(0, os.environ.get('FSVG_DIR', '/root/fsvg'))
    try:
        import fsvgc
        available = {k.upper() for k in fsvgc.ARITY}
    except Exception as e:
        ap.error('cannot import fsvgc to check which ops exist (%s). Set '
                 'FSVG_DIR to the fsvg repo.' % e)

    unknown = {}
    for sid, kind, label, line, n in FLOW:
        for part in (n or '').split('+'):
            part = part.strip()
            if part and part.upper() not in available:
                unknown.setdefault(part, []).append(sid)
    missing = sum(len(v) for v in unknown.values())

    if missing:
        deficit = '<b>%d</b> shapes need ops fsvgc lacks' % missing
        legend = ('missing ops: ' + ' '.join(
            '<span class=k>%s</span>' % k for k in sorted(unknown)))
    else:
        deficit = 'every op it uses exists in fsvgc'
        legend = ('ops used: ' + ' '.join(
            '<span class=k>%s</span>' % k for k in sorted(
                {p.strip() for *_x, n in FLOW for p in (n or '').split('+') if p.strip()})))

    doc = f"""<!doctype html><meta charset="utf-8">
<title>FSVG &middot; {a.title}</title><style>{CSS}</style>
<header>
  <h1>FSVG &middot; {html.escape(a.title)}</h1>
  <span><b>{len(rows)}</b> real instructions</span>
  <span><b>{len(keep)}</b> source lines</span>
  <span><b>{len(FLOW)}</b> flow shapes</span>
  <span>{deficit}</span>
  <span>click anything &mdash; Esc clears</span>
</header>
<main>
  <pane><h2>1 &middot; FSVG flowchart</h2>{build_svg()}
    <div class="legend">{legend}</div></pane>
  <pane><h2>2 &middot; generated assembly (real trace)</h2>{build_asm_rows(rows)}</pane>
  <pane><h2>3 &middot; original Linux source</h2>{build_src(a.kernel, a.entry, a.lo, a.hi, keep)}</pane>
</main>
<script>{JS}</script>"""
    open(a.out, 'w').write(doc)
    print(f"{a.out}  {len(doc)} bytes  |  {len(rows)} insn  |  {len(keep)} src lines"
          f"  |  {len(FLOW)} shapes  |  "
          + ("%d need new ops" % missing if missing
             else "all ops it uses exist"))

if __name__ == '__main__':
    main()