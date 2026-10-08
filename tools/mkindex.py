#!/usr/bin/env python3
"""
mkindex.py -- build the GitHub Pages landing page.

Lists every built three-pane page under kernel/, with the counts each one
reports, so the index can never drift from what build.sh actually produced.
"""
import argparse, glob, html, os, re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def stats(path):
    """Pull the counters straight out of the generated page."""
    s = open(path).read()
    def n(pat):
        m = re.search(pat, s)
        return int(m.group(1)) if m else 0
    return dict(insn=n(r'<b>(\d+)</b> real instructions'),
                lines=n(r'<b>(\d+)</b> source lines'),
                shapes=n(r'<b>(\d+)</b> flow shapes'),
                missing=n(r'<b>(\d+)</b> shapes need ops'))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=os.path.join(HERE, 'index.html'))
    a = ap.parse_args()

    rows = []
    for dirpath, _dirs, files in os.walk(os.path.join(HERE, 'kernel')):
        for f in sorted(files):
            if not f.endswith('.html'):
                continue
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, HERE)
            rel_src = rel.replace('kernel/', '').replace('.html', '')
            rows.append((rel, rel_src, stats(full)))
    rows.sort()

    cards = []
    # The Boot Factory is a fixed artefact, not a per-file unit, so the walk above
    # never finds it. Its numbers are read out of the built page rather than typed
    # in — a hand-written count is the one thing that reliably goes stale here.
    fp = os.path.join(HERE, 'factory.html')
    if os.path.exists(fp):
        fh = open(fp, encoding='utf-8', errors='replace').read()
        mt = re.search(r'"total":(\d+)', fh)
        mb = re.search(r'"beats":\[([0-9,]*)\]', fh)
        if mt:
            nb = len([x for x in (mb.group(1).split(',') if mb else []) if x])
            ni = len(glob.glob(os.path.join(HERE, 'img', 'beat-*.png')))
            cards.append(f"""    <a class="card ok" href="factory.html">
      <div class="path">arch/x86/kernel/head_64.S &mdash; Boot Factory</div>
      <div class="nums">
        <span><b>{mt.group(1)}</b> instructions executed</span>
        <span><b>{nb}</b> hardware beats</span>
        <span><b>{ni}</b> before/after images</span>
        <span><b>1</b> robot</span>
      </div>
      <div class="state ok">the first hardware the kernel touches &mdash; a robot moves every value</div>
    </a>""")
    for rel, rel_src, st in rows:
        state = ('compiling' if st['missing'] == 0 else 'needs ops')
        cls = 'ok' if st['missing'] == 0 else 'todo'
        cards.append(f"""    <a class="card {cls}" href="{html.escape(rel)}">
      <div class="path">{html.escape(rel_src)}</div>
      <div class="nums">
        <span><b>{st['insn']}</b> instructions</span>
        <span><b>{st['lines']}</b> source lines</span>
        <span><b>{st['shapes']}</b> shapes</span>
      </div>
      <div class="state {cls}">{state}</div>
    </a>""")

    if not cards:
        cards.append('    <p class="empty">Nothing built yet - run <code>./build.sh</code>.</p>')

    doc = f"""<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fsvg-linux</title><style>
:root{{color-scheme:dark}}
*{{box-sizing:border-box}}
body{{margin:0;background:#0d1117;color:#c9d1d9;
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
.wrap{{max-width:860px;margin:0 auto;padding:40px 20px 64px}}
h1{{font-size:28px;margin:0 0 6px;color:#58a6ff}}
.tag{{color:#8b949e;margin:0 0 4px;font-size:15px}}
.why{{color:#6e7681;font-size:13px;margin:0 0 32px}}
h2{{font-size:12px;letter-spacing:.09em;text-transform:uppercase;color:#8b949e;
  margin:0 0 12px}}
.grid{{display:grid;gap:12px}}
.card{{display:block;padding:16px 18px;border:1px solid #21262d;border-radius:8px;
  background:#161b22;text-decoration:none;color:inherit;transition:border-color .12s}}
.card:hover{{border-color:#58a6ff}}
.card.ok{{border-left:3px solid #3fb950}}
.card.todo{{border-left:3px solid #d29922}}
.path{{font:14px ui-monospace,Menlo,Consolas,monospace;color:#e6edf3;margin-bottom:8px}}
.nums{{display:flex;gap:18px;flex-wrap:wrap;color:#8b949e;font-size:13px}}
.nums b{{color:#c9d1d9;font-weight:600}}
.state{{margin-top:10px;font-size:12px}}
.state.ok{{color:#3fb950}}
.state.todo{{color:#d29922}}
.empty{{color:#6e7681}}
code{{background:#161b22;padding:1px 5px;border-radius:4px;font-size:13px}}
footer{{margin-top:40px;padding-top:16px;border-top:1px solid #21262d;
  color:#6e7681;font-size:13px}}
footer a{{color:#58a6ff}}
</style>
<div class="wrap">
  <h1>fsvg-linux</h1>
  <p class="tag">Linux in my language. The kernel, rewritten in a flowchart language.</p>
  <p class="why">Every file is shown three ways at once &mdash; our diagram, the assembly the CPU
     actually executed, and the original kernel source. Click anything in one pane and it
     lights up in the other two.</p>
  <h2>Translated files</h2>
  <div class="grid">
{chr(10).join(cards)}
  </div>
  <footer>
    Language and compiler: <a href="https://github.com/ArslanCS1993/fsvg">fsvg</a> &middot;
    Trace data: <a href="https://github.com/ArslanCS1993/cpu-3d">cpu-3d</a>
  </footer>
</div>"""
    open(a.out, 'w').write(doc)
    print(f"{a.out}  {len(doc)} bytes  |  {len(rows)} page(s) indexed")

if __name__ == '__main__':
    main()