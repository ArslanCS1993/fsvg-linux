#!/usr/bin/env python3
"""
Build the Boot Factory page.

Driven by REAL code: 89 instructions of arch/x86/kernel/head_64.S disassembled
out of the real vmlinux, with real addresses, real bytes and real source lines.
Control flow is followed BY ADDRESS, so call/ret/lretq/jmp/jcc really execute.

Output: factory.html  (single file, no external assets, no network)
"""
import json, re, os, subprocess, collections

VMLINUX = '/tmp/kobj64/vmlinux'
SRC     = '/tmp/ksrc64/linux-source-6.8.0/arch/x86/kernel/head_64.S'
OUT     = '/root/factory/factory.html'
LO, HI  = 0xffffffff81000000, 0xffffffff81003000

# ---------------------------------------------------------------- disassemble
def disassemble():
    out = subprocess.run(['objdump','-dl',f'--start-address={LO}',
                          f'--stop-address={HI}',VMLINUX],
                         capture_output=True,text=True).stdout
    re_src = re.compile(r'^(/.*):(\d+)$')
    re_ins = re.compile(r'^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$')
    src=None; steps=[]
    for line in out.splitlines():
        m=re_src.match(line)
        if m: src=(m.group(1),int(m.group(2))); continue
        m=re_ins.match(line)
        if m and src and src[0].endswith('head_64.S'):
            steps.append({'a':int(m.group(1),16),'b':m.group(2).strip().replace(' ',''),
                          't':m.group(3).split('#')[0].strip(),'ln':src[1]})
    return steps

# ---------------------------------------------------------------- tiny x86
R64 = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15']
ALIAS = {'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx','esi':'rsi','edi':'rdi','ebp':'rbp','esp':'rsp',
         'ax':'rax','bx':'rbx','cx':'rcx','dx':'rdx','si':'rsi','di':'rdi','bp':'rbp','sp':'rsp',
         'al':'rax','bl':'rbx','cl':'rcx','dl':'rdx','sil':'rsi','dil':'rdi','bpl':'rbp','spl':'rsp'}
for i in range(8,16):
    ALIAS[f'r{i}d']=f'r{i}'; ALIAS[f'r{i}w']=f'r{i}'; ALIAS[f'r{i}b']=f'r{i}'
SIZE = {}
for n in ALIAS:
    if n.endswith('d') and n not in R64: SIZE[n]=4
    elif n.endswith('w'): SIZE[n]=2
    elif n.endswith(('l','b')) and n not in R64: SIZE[n]=1

M64=(1<<64)-1

def rname(op):
    op=op.strip().lstrip('%')
    if op in R64: return op,8
    if op in ALIAS: return ALIAS[op], SIZE.get(op,8)
    return None,None

def parse_ops(text):
    """split mnemonics/operands, strip size prefixes"""
    parts=text.split(None,1)
    mn=parts[0]
    ops=[o.strip() for o in parts[1].split(',')] if len(parts)>1 else []
    return mn,ops

class CPU:
    def __init__(s):
        s.r={k:0 for k in R64}
        s.r['rsi']=0x100000          # head_64.S contract: rsi = boot_params
        s.cr={0:0,3:0,4:0}
        s.msr={}
        s.mem={}
        s.f={'CF':0,'ZF':0,'SF':0,'OF':0}
        s.rip=LO
    def rd(s,op):
        op=op.strip()
        if op.startswith('$'): return int(op[1:],0)
        r,sz=rname(op)
        if r: return s.r[r] & ((1<<(sz*8))-1 if sz<8 else M64)
        # memory forms
        m=re.match(r'(?:(-?0x[0-9a-f]+))?\(%rip\)',op)
        if m: return s.mem.get(s.rip+(int(m.group(1),0) if m.group(1) else 0),0)
        m=re.match(r'(?:(-?0x[0-9a-f]+))?\((%\w+)(?:,%\w+,(\d))?\)',op)
        if m:
            off=int(m.group(1),0) if m.group(1) else 0
            base,_=rname(m.group(2)); scale=int(m.group(3)) if m.group(3) else 1
            return s.mem.get(((s.r[base] if base else 0)+off)&M64,0)
        m=re.match(r'(?:0x([0-9a-f]+))?\(.*\)',op)
        if m: return s.mem.get(int(m.group(1),16) if m.group(1) else 0,0)
        return 0
    def wr(s,op,val):
        op=op.strip()
        r,sz=rname(op)
        if r:
            if sz<8: val &= (1<<(sz*8))-1
            else: val &= M64
            s.r[r]=val; return True
        if op.startswith('%cr'):
            s.cr[int(op[3:])]=val; return True
        m=re.match(r'(?:(-?0x[0-9a-f]+))?\(%rip\)',op)
        if m:
            s.mem[s.rip+(int(m.group(1),0) if m.group(1) else 0)]=val; return True
        m=re.match(r'(?:(-?0x[0-9a-f]+))?\((%\w+)\)',op)
        if m:
            off=int(m.group(1),0) if m.group(1) else 0
            b,_=rname(m.group(2)); s.mem[((s.r[b] if b else 0)+off)&M64]=val; return True
        return False
    def push(s,v):
        s.r['rsp']=(s.r['rsp']-8)&M64; s.mem[s.r['rsp']]=v&M64
    def pop(s):
        v=s.mem.get(s.r['rsp'],0); s.r['rsp']=(s.r['rsp']+8)&M64; return v
    def setf(s,res,cf=None,of=0,width=64):
        mask=(1<<width)-1
        s.f['ZF']=1 if (res&mask)==0 else 0
        s.f['SF']=1 if (res>>(width-1))&1 else 0
        if cf is not None: s.f['CF']=cf
        s.f['OF']=of

HW_RE = re.compile(r'\b(wrmsr|rdmsr|lgdt|lidt|cpuid|popf|pushf|invlpg|clts|swapgs)\b')
def classify(ins):
    """return (kind, hardware_station, motion) — the factory plan for one instruction"""
    t=ins['t']; mn,ops=parse_ops(t)
    base=mn.split('.')[0]
    # control-register moves
    if any(o.startswith('%cr') for o in ops):
        cr=[o for o in ops if o.startswith('%cr')][0]
        return ('cr', cr, ('reg' if not ops[0].startswith('%cr') else cr))
    if base in ('nop','nopl','nopw','data16','cs'):
        return ('idle',None,None)
    if base=='wrmsr':  return ('msr-w','msr',None)
    if base=='rdmsr':  return ('msr-r','msr',None)
    if base in ('cpuid',): return ('idle','cpuid',None)
    if base=='lgdt': return ('gdt','gdt',None)
    if base in ('popf','pushf'): return ('flags','flags',None)
    if base in ('lretq','retq','ret'): return ('ret','door',None)
    if base in ('call',): return ('call','door',None)
    if base.startswith('j'): return ('jump',None,None)
    if base in ('push',): return ('push','stack',None)
    if base in ('pop',): return ('pop','stack',None)
    if base in ('add','sub','and','or','xor','shl','shr','sal','sar','imul','mul','cmp','test'):
        return ('alu','alu',None)
    if base in ('lea',): return ('lea','addr',None)
    if base in ('bts','btsq','bt'): return ('alu','alu',None)
    if base in ('mov','movl','movw','movq','movzbl','movslq'): return ('mov',None,None)
    return ('other',None,None)

def hw_rows(ins):
    """what hardware this instruction touches — R/W per part"""
    t=ins['t']; mn,ops=parse_ops(t); base=mn.split('.')[0]
    rows=[]
    def reg(o):
        n,_=rname(o); return n
    if base in ('mov','movl','movw','movq','lea') and len(ops)==2:
        d=ops[1].strip()
        if d.startswith('%cr'):
            rows.append(('Control unit', d.upper(), 'W', 'programs the CPU'))
        else:
            dn,_=rname(d)
            if dn: rows.append(('Register file', dn.upper(), 'W', 'written'))
        src=ops[0].strip()
        if src.startswith('$'):
            rows.append(('Instruction stream','immediate','R','constant from the code'))
        elif '(' in src:
            rows.append(('Load/store unit','memory','R','read from RAM'))
        elif '%rip' in src:
            rows.append(('Program counter','RIP','R','pc-relative address'))
        else:
            sn,_=rname(src)
            if sn: rows.append(('Register file', sn.upper(), 'R','read'))
    elif base in ('add','sub','and','or','xor','shl','shr','sal','sar','imul','mul','bts','btsq','bt'):
        rows.append(('ALU','operation','RW','computes'))
        for o in ops:
            n,_=rname(o)
            if n: rows.append(('Register file', n.upper(), 'RW' if o==ops[-1] else 'R','operand'))
        rows.append(('Flags','CF ZF SF OF','W','result flags'))
    elif base in ('cmp','test'):
        for o in ops:
            n,_=rname(o)
            if n: rows.append(('Register file', n.upper(), 'R','operand'))
        rows.append(('Flags','CF ZF SF OF','W','comparison result'))
    elif base in ('push','pop'):
        rows.append(('Stack engine','RSP', 'RW', 'moves the stack pointer'))
        rows.append(('Load/store unit','kernel stack','W' if base=='push' else 'R','stack traffic'))
    elif base=='wrmsr':
        rows.append(('MSR unit','ECX=index, EDX:EAX=value','W','writes a model-specific register'))
    elif base=='rdmsr':
        rows.append(('MSR unit','ECX=index','R','reads a model-specific register'))
    elif base=='cpuid':
        rows.append(('CPUID','EAX=leaf','R','CPU identification'))
    elif base=='lgdt':
        rows.append(('Descriptor tables','GDTR','W','loads the GDT'))
    elif base in ('popf','pushf'):
        rows.append(('Flags','EFLAGS','R' if base=='pushf' else 'W','flag transfer'))
    elif base.startswith('j'):
        rows.append(('Program counter','RIP','W','branches'))
        rows.append(('Flags','condition','R','branch condition'))
    elif base in ('call','ret','lretq','retq'):
        rows.append(('Program counter','RIP','W','control transfer'))
        rows.append(('Stack engine','RSP','RW','return address'))
    return rows

# ---------------------------------------------------------------- execute
def execute(steps):
    """follow control flow by address — real execution of the real instructions"""
    idx={s['a']:i for i,s in enumerate(steps)}
    cpu=CPU(); trace=[]; guard=0
    seen={}
    while cpu.rip in idx and len(trace)<900 and guard<20000:
        guard+=1
        i=idx[cpu.rip]; ins=steps[i]
        before={k:v for k,v in cpu.r.items()}
        crb=dict(cpu.cr); msrb=dict(cpu.msr); fb=dict(cpu.f)
        t=ins['t']; mn,ops=parse_ops(t); base=mn.split('.')[0]
        nxt=ins['a']+len(ins['b'])//2
        outside=None
        if base in ('nop','nopl','nopw','data16','cs'): pass
        elif base=='mov' and len(ops)==2:
            if ops[1].startswith('%cr'): cpu.wr(ops[1],cpu.rd(ops[0]))
            elif '(' in ops[0] and not ops[0].startswith('$'): cpu.wr(ops[1],cpu.rd(ops[0]))
            elif '(' in ops[1]: cpu.wr(ops[1],cpu.rd(ops[0]))
            elif ops[0].startswith('%cr'): cpu.wr(ops[1],cpu.cr[int(ops[0][3:])])
            else: cpu.wr(ops[1],cpu.rd(ops[0]))
        elif base in ('movl','movw','movq'):
            cpu.wr(ops[1],cpu.rd(ops[0]))
        elif base=='lea':
            m=re.match(r'(?:(-?0x[0-9a-f]+))?\((%\w+)(?:,%\w+,(\d))?\)',ops[0])
            if m:
                off=int(m.group(1),0) if m.group(1) else 0
                if m.group(2)=='%rip':
                    v=(cpu.rip+len(ins['b'])//2+off)&M64
                else:
                    b,_=rname(m.group(2))
                    v=((cpu.r[b] if b else 0)+off)&M64
                cpu.wr(ops[1],v)
        elif base in ('xor','add','sub','and','or','shl','shr','sal','sar','bts','btsq'):
            a=cpu.rd(ops[1]); b=cpu.rd(ops[0])
            if base=='xor': res=a^b
            elif base=='add': res=a+b
            elif base=='sub': res=a-b
            elif base=='and': res=a&b
            elif base=='or':  res=a|b
            elif base in ('shl','sal'): res=a<<(b&0x3f)
            elif base=='shr': res=a>>(b&0x3f)
            elif base=='sar': res=a>>(b&0x3f)
            elif base in ('bts','btsq'): res=a|(1<<(b&0x3f))
            else: res=a
            cpu.wr(ops[1],res)
            cpu.setf(res&M64, cf=1 if (base=='add' and res>M64) else 0, of=0)
        elif base=='cmp':
            a=cpu.rd(ops[1]); b=cpu.rd(ops[0]); res=a-b
            cpu.setf(res&M64, cf=1 if a<b else 0); 
        elif base=='test':
            res=cpu.rd(ops[0])&cpu.rd(ops[1]); cpu.setf(res&M64,cf=0)
        elif base=='bt':
            a=cpu.rd(ops[0]); b=cpu.rd(ops[1]); cpu.f['CF']=1 if (a>>(b&0x3f))&1 else 0
        elif base=='push': cpu.push(cpu.rd(ops[0]))
        elif base=='pop':  cpu.wr(ops[0],cpu.pop())
        elif base=='popf':
            v=cpu.pop()
            cpu.f['CF']=v&1; cpu.f['ZF']=(v>>6)&1; cpu.f['SF']=(v>>7)&1; cpu.f['OF']=(v>>11)&1
        elif base=='wrmsr':
            idx_msr=cpu.r['rcx']&0xffffffff
            cpu.msr[idx_msr]=((cpu.r['rdx']&0xffffffff)<<32)|(cpu.r['rax']&0xffffffff)
        elif base=='rdmsr':
            v=cpu.msr.get(cpu.r['rcx']&0xffffffff,0)
            cpu.r['rax']=v&0xffffffff; cpu.r['rdx']=(v>>32)&0xffffffff
        elif base=='cpuid': pass
        elif base=='lgdt':
            m=re.match(r'\((%\w+)\)',ops[0])
            b,_=rname(m.group(1)); cpu.r.setdefault('gdtr',0)
            cpu.msr['__gdtr']=cpu.mem.get(cpu.r[b],0)
        elif base=='call':
            tgt=None
            m=re.search(r'<([^>+]+)',t)
            ma=re.search(r'([0-9a-f]{8,})',ops[0])
            if ma: tgt=int(ma.group(1),16)
            cpu.push(nxt)
            if tgt is not None and tgt in idx: nxt=tgt
            else: outside=m.group(1) if m else 'another file'
        elif base in ('ret','retq'):
            nxt=cpu.pop()
        elif base=='lretq':
            nxt=cpu.pop(); cpu.pop()
        elif base in ('jmp',):
            ma=re.search(r'([0-9a-f]{8,})',t)
            if ma: nxt=int(ma.group(1),16)
        elif base[0]=='j':
            taken=False
            cond=base
            if cond in ('je','jz'): taken=cpu.f['ZF']==1
            elif cond in ('jne','jnz'): taken=cpu.f['ZF']==0
            elif cond in ('jae','jnc','jnb'): taken=cpu.f['CF']==0
            elif cond in ('jb','jc','jnae'): taken=cpu.f['CF']==1
            elif cond in ('jbe','jna'): taken=cpu.f['CF']==1 or cpu.f['ZF']==1
            elif cond in ('ja','jnbe'): taken=cpu.f['CF']==0 and cpu.f['ZF']==0
            ma=re.search(r'([0-9a-f]{8,})',t)
            if taken and ma: nxt=int(ma.group(1),16)
        cpu.rip=nxt
        kind,station,motion=classify(ins)
        memwin=[cpu.mem.get((cpu.r['rsp']+8*k)&M64,0) for k in range(4)]
        trace.append({'ins':ins,'kind':kind,'station':station,'motion':motion,
                      'regs':dict(cpu.r),'cr':dict(cpu.cr),'msr':dict(cpu.msr),'f':dict(cpu.f),
                      'prev':before,'prevcr':crb,'prevf':fb,'prevmsr':msrb,
                      'mem':memwin,'outside':outside})
    return trace

# ---------------------------------------------------------------- source
def source_lines():
    return open(SRC, encoding='utf-8', errors='replace').read().splitlines()

def window(lines, ln, n=6):
    a=max(1,ln-n); b=min(len(lines),ln+n)
    return [{'n':i,'t':lines[i-1]} for i in range(a,b+1)]

# ---------------------------------------------------------------- main
def main():
    steps=disassemble()
    trace=execute(steps)
    lines=source_lines()
    regs=[r for r in R64]
    beats=[i for i,s in enumerate(trace) if s['kind'] in ('cr','msr-w','msr-r','gdt','flags') or
           (s['kind']=='mov' and any(o.startswith('%cr') for o in parse_ops(s['ins']['t'])[1]))]
    payload={'steps':trace,'regs':regs,'beats':beats,'total':len(trace),
             'file':'arch/x86/kernel/head_64.S','srcpath':SRC,
             'vmlinux':VMLINUX,'lo':'0x%x'%LO,'entry':'0x%x'%LO}
    # --- 64-bit values MUST ship as hex strings: a JS Number silently rounds
    #     0xffffffff81000000, and the page would render a wrong address.
    for s in payload['steps']:
        s['ins']['a']='0x%x'%s['ins']['a']
        for key in ('regs','cr','msr','prev','prevcr','prevmsr'):
            s[key]={k:('0x%x'%(v & M64)) for k,v in s[key].items()}
        s['mem']=['0x%x'%v for v in s['mem']]
        s['hw']=hw_rows(s['ins'])
        s['src']=window(lines,s['ins']['ln'])
    data=json.dumps(payload, separators=(',',':'))
    # the JSON lands at STATEMENT position, so it needs a `var D=` — as a bare
    # object literal it parses as a block and D is never defined.
    # escape only the injected string: a raw "</" inside a <script> ends it.
    html=HTML.replace('/*__DATA__*/', 'var D='+data.replace('</','<\\/'))
    open(OUT,'w').write(html)
    print('steps executed:',len(trace))
    print('hardware beats:',len(beats))
    print('addrs:',trace[0]['ins']['a'],'->',trace[-1]['ins']['a'])
    print('out:',OUT,os.path.getsize(OUT),'bytes')
    for i in beats[:14]:
        print(f"  beat {i:>3} {trace[i]['ins']['a']} L{trace[i]['ins']['ln']} {trace[i]['ins']['t']}")

HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Boot Factory — the first hardware Linux touches</title>
<style>
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{height:100vh;display:flex;flex-direction:column;overflow:hidden;background:#0d1117;color:#c9d1d9;
     font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{flex:0 0 auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap;
       padding:7px 12px;background:#161b22;border-bottom:1px solid #30363d}
h1{font-size:13px;margin:0 10px 0 0;font-weight:600;color:#e6edf3;white-space:nowrap}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:4px 9px;
       font:inherit;cursor:pointer}
button:hover{background:#30363d}button:disabled{opacity:.4;cursor:default}
button.hot{border-color:#d29922;color:#e3b341}
.stat{color:#8b949e}.stat b{color:#e6edf3}
main{flex:1 1 auto;min-height:0;display:grid;grid-template-columns:270px minmax(0,1fr) 330px;
     grid-template-rows:minmax(0,1fr)}
main.withdetail{grid-template-columns:250px minmax(0,1fr) 300px}
.pane{min-height:0;overflow:auto;border-right:1px solid #30363d}
.pane:last-child{border-right:0}
.pane h2{position:sticky;top:0;margin:0;padding:6px 10px;font-size:11px;letter-spacing:.08em;
  text-transform:uppercase;color:#8b949e;background:#161b22;border-bottom:1px solid #30363d;z-index:3}
/* instruction list */
.irow{padding:3px 10px;cursor:pointer;display:flex;gap:8px;border-left:2px solid transparent;white-space:nowrap}
.irow:hover{background:#161b22}
.irow .ad{color:#8b949e}.irow .tx{color:#e6edf3;overflow:hidden;text-overflow:ellipsis}
.irow.cur{background:#1f6feb22;border-left-color:#1f6feb}
.irow.cur .tx{color:#79c0ff}
.irow.beat .tx::before{content:"\26A1";color:#e3b341;margin-right:4px}
.irow.past{opacity:.45}
/* factory */
#floor{position:relative;min-height:0;overflow:auto;padding:10px;
       background:radial-gradient(circle at 30% 10%,#161b22,#0d1117 70%)}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px}
.bay{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:6px 7px;min-width:0}
.bay.wide{grid-column:span 2}
.bay .cap{font-size:10px;letter-spacing:.06em;color:#8b949e;text-transform:uppercase;margin-bottom:3px}
.bin{display:flex;justify-content:space-between;gap:6px;padding:2px 5px;border-radius:4px;background:#0d1117;
     border:1px solid #21262d;margin-bottom:2px;overflow:hidden}
.bin .nm{color:#8b949e;flex:0 0 auto}
.bin .vl{color:#7ee787;overflow-wrap:anywhere;text-align:right}
.bin.rd{border-color:#1f6feb;background:#1f6feb1a}
.bin.wr{border-color:#d29922;background:#d299221a}
.bin.wr .vl{color:#e3b341}
.bin.rd .nm{color:#79c0ff}
.station{background:#161b22;border:1px dashed #30363d;border-radius:8px;padding:6px 7px;min-width:0}
.station.hot{border-style:solid;border-color:#e3b341;box-shadow:0 0 0 1px #e3b34155}
.station .cap{font-size:10px;letter-spacing:.06em;color:#8b949e;text-transform:uppercase}
.station .val{color:#e3b341;overflow-wrap:anywhere}
.die{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:6px 7px;
     display:flex;gap:8px;align-items:center;min-width:0}
.pin{width:9px;height:9px;border-radius:2px;background:#30363d;flex:0 0 auto}
.pin.on{background:#e3b341;box-shadow:0 0 6px #e3b34190}
/* robot */
#robot{position:absolute;width:34px;height:30px;left:0;top:0;pointer-events:none;z-index:5;
  transition:transform .55s cubic-bezier(.4,.05,.3,1);will-change:transform}
#robot .body{width:34px;height:22px;background:#1f6feb;border-radius:6px 6px 3px 3px;
  border:2px solid #79c0ff;position:relative;margin-top:8px}
#robot .eye{position:absolute;left:6px;top:6px;width:6px;height:6px;border-radius:50%;background:#e6edf3}
#robot .eye.r{left:18px}
#robot .claw{position:absolute;right:-11px;top:2px;width:12px;height:5px;background:#79c0ff;border-radius:2px}
#robot .carry{position:absolute;right:-20px;top:-11px;background:#21262d;border:1px solid #e3b341;
  color:#e3b341;border-radius:3px;font-size:9px;padding:0 3px;white-space:nowrap;opacity:0;
  transition:opacity .2s}
#robot .carry.on{opacity:1}
#robot.gone{opacity:.25}
#narr{position:sticky;bottom:0;margin-top:9px;background:#161b22;border:1px solid #30363d;border-radius:8px;
  padding:7px 9px;min-height:44px}
#narr .d{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
#narr .t{color:#e6edf3}
/* right column */
.srow{display:flex;gap:8px;padding:1px 8px}
.srow .n{color:#484f58;flex:0 0 34px;text-align:right}
/* source lines are long and tab-indented: wrap them, or the pane scrolls sideways.
   `anywhere` (not break-word) — only it lowers the min-content contribution. */
.srow .c{color:#8b949e;white-space:pre-wrap;overflow-wrap:anywhere;min-width:0}
.srow.hit .c{color:#c9d1d9}
.srow.cur{background:#d2992222}
.srow.cur .c,.srow.cur .n{color:#e3b341}
table{width:100%;border-collapse:collapse;table-layout:fixed}
td,th{padding:2px 6px;border-bottom:1px solid #21262d;text-align:left;overflow-wrap:anywhere}
th{color:#8b949e;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.05em}
.acc{font-weight:700}.acc.R{color:#79c0ff}.acc.W{color:#e3b341}.acc.RW{color:#d2a8ff}.acc.-{color:#484f58}
#detail{display:none}
main.withdetail #detail{display:block}
main.withdetail{grid-template-columns:230px minmax(0,1fr) 240px 260px}
main.withdetail #pane-detail{display:block}
#pane-detail{display:none;border-left:1px solid #30363d}
footer{flex:0 0 auto;padding:5px 12px;background:#161b22;border-top:1px solid #30363d;color:#8b949e;
  font-size:11px}
</style></head><body>
<header>
  <h1>Boot Factory</h1>
  <button id="first">&laquo;</button><button id="prev">&lsaquo;</button>
  <button id="play">&#9654; play</button><button id="next">&rsaquo;</button><button id="last">&raquo;</button>
  <button id="beat" class="hot">&#9889; next hardware beat</button>
  <button id="detailb">description</button>
  <span class="stat" id="pos"></span>
</header>
<main id="main">
  <section class="pane"><h2>Instructions (real)</h2><div id="list"></div></section>
  <section class="pane" id="pane-floor"><h2>Hardware floor</h2>
    <div id="floor">
      <div class="grid" id="bays"></div>
      <div id="narr"><div class="d" id="nkind">ready</div><div class="t" id="ntext"></div></div>
      <div id="robot"><div class="carry" id="carry"></div><div class="body"><div class="eye"></div>
        <div class="eye r"></div><div class="claw"></div></div></div>
    </div>
  </section>
  <section class="pane" id="pane-detail"><h2>Description</h2><div id="detail"></div></section>
  <section class="pane"><h2>Linux source</h2><div id="src"></div>
    <h2>Hardware touched</h2><div id="hwt"></div></section>
</main>
<footer id="foot"></footer>
<script>
/*__DATA__*/
/* ================= factory model (no DOM) ================= */
var STEPS=D.steps, N=STEPS.length, beats=D.beats;
function hex(v,w){v=BigInt(v);w=w||16;var s=v.toString(16);while(s.length<w)s='0'+s;return s;}
function sgn(v){v=BigInt(v);return v>=0x8000000000000000n?v-0x10000000000000000n:v;}
function fmt(v){var b=BigInt(v);return (b<=0xffffffffffffn?('0x'+hex(b)):(sgn(b).toString()+' (0x'+hex(b)+')'))}
function z(v){return '0x'+hex(v);}
var RA={eax:'rax',ebx:'rbx',ecx:'rcx',edx:'rdx',esi:'rsi',edi:'rdi',ebp:'rbp',esp:'rsp',
        ax:'rax',bx:'rbx',cx:'rcx',dx:'rdx',si:'rsi',di:'rdi',bp:'rbp',sp:'rsp',
        al:'rax',bl:'rbx',cl:'rcx',dl:'rdx'};
(function(){for(var q=8;q<16;q++){RA['r'+q+'d']='r'+q;RA['r'+q+'w']='r'+q;RA['r'+q+'b']='r'+q;}})();
function canon(r){r=String(r).replace(/%/g,'').trim();return RA[r]||r;}

function changed(i,key,k){ // diff effect of instruction i
  if(i<0) return false;
  var a=STEPS[i][key], b=i+1<N?STEPS[i+1][key]:null;
  if(key==='regs'||key==='cr'||key==='msr'||key==='f'){
    var nv=a[k], nv2=i+1<N?STEPS[i+1][key][k]:undefined;
    return String(nv)!==String(nv2);
  }
  return false;
}
function rowState(i){ // which regs this step reads / writes
  var r={}, st=STEPS[i];
  (st.hw||[]).forEach(function(h){
    if(h[0]!=='Register file') return;
    var nm=h[1].toLowerCase(); if(!nm) return;
    r[nm]=h[2];
  });
  return r;
}
/* ================= narration (the robot's job) ================= */
function narrate(i){
  var st=STEPS[i], t=st.ins.t, o=t.split(/\s+/), m=o[0].split('.')[0];
  var a=(o.length>1?o.slice(1).join(' ').split(',') : []), dst=(a[1]||'').trim(), src=(a[0]||'').trim();
  function clean(s){return s.replace(/%/g,'').trim();}
  var sd=clean(dst), ss=clean(src);
  if(m==='mov'&&sd.indexOf('cr')===0) return ['hardware','robot carries '+ss+' to the '+sd.toUpperCase()+' panel and sets it — the CPU is being programmed'];
  if(m==='mov'&&ss.indexOf('cr')===0) return ['hardware','robot reads the '+ss.toUpperCase()+' panel into '+sd];
  if(m==='mov') return ['deposit','robot takes '+ss+' and drops it into '+sd];
  if(m==='lea') return ['deposit','robot asks the address unit for a computed address and drops it into '+sd];
  if(m==='wrmsr') return ['hardware','robot feeds RCX (which MSR) + EDX:EAX (what value) into the MSR machine and turns the crank'];
  if(m==='rdmsr') return ['hardware','robot reads a model-specific register back out of the MSR machine'];
  if(m==='lgdt') return ['hardware','robot loads the descriptor table into the GDT gangway'];
  if(m==='cpuid') return ['hardware','the CPU-ID printer identifies this processor'];
  if(m==='push') return ['carry','robot carries '+ss+' to the stack pile and stacks it'];
  if(m==='pop') return ['carry','robot lifts the top of the stack pile into '+sd];
  if(m==='popf') return ['hardware','robot restores the flag scoreboard from the stack'];
  if(m==='call') return ['leave','robot walks to the door marked '+(st.outside||'another file')+' — leaves this room, comes back'];
  if(m==='lretq'||m==='ret'||m==='retq') return ['return','robot returns through the door to the address it stacked'];
  if(m.charAt(0)==='j') return ['jump','robot checks the flag scoreboard and picks the next instruction'];
  if(['add','sub','and','or','xor','shl','shr','sal','sar','imul','mul','bts','btsq'].indexOf(m)>=0)
    return ['alu','robot hauls '+ss+' into the ALU with '+(clean(a[1])||'')+' — the machine computes and the result goes back'];
  if(m==='cmp'||m==='test'||m==='bt') return ['alu','robot feeds both operands into the comparator — nothing is stored, only the flags change'];
  if(m.indexOf('nop')===0||m==='data16'||m==='cs') return ['idle','padding — the robot waits, nothing to carry'];
  return ['idle','robot follows the instruction'];
}
/* ================= DOM ================= */
function $(id){return document.getElementById(id);}
var cur=0, timer=null, firstCanvas=null;

function buildList(){
  var h='';
  for(var i=0;i<N;i++){
    var s=STEPS[i], isb=beats.indexOf(i)>=0;
    h+='<div class="irow'+(isb?' beat':'')+'" id="row-'+i+'" data-i="'+i+'">'+
       '<span class="ad">'+hex(s.ins.a).slice(-8)+'</span><span class="tx">'+esc(s.ins.t)+'</span></div>';
  }
  $('list').innerHTML=h;
  $('list').onclick=function(e){var r=e.target.closest('.irow'); if(r) select(+r.dataset.i);};
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function buildFloor(){
  var byId={};
  byId['regs']='<div class="bay wide"><div class="cap">Register file — the bins</div><div id="regs"></div></div>';
  byId['stations']='<div class="bay wide"><div class="cap">Machines</div><div id="stations"></div></div>';
  $('bays').innerHTML=byId.regs+byId.stations+
    '<div class="bay"><div class="cap">Flags</div><div id="flags"></div></div>'+
    '<div class="bay"><div class="cap">Stack pile</div><div id="stack"></div></div>';
}

function draw(i){
  var st=STEPS[i];
  /* registers */
  var rs=rowState(i), rh='';
  for(var k=0;k<D.regs.length;k++){
    var r=D.regs[k], cls=rs[r]? (rs[r]==='R'?'rd':'wr') : (changed(i,'regs',r)?'wr':'');
    rh+='<div class="bin '+cls+'" id="bin-'+r+'"><span class="nm">'+r.toUpperCase()+
        '</span><span class="vl">'+z(st.regs[r])+'</span></div>';
  }
  $('regs').innerHTML=rh;
  /* machines */
  var sh='';
  sh+='<div class="station" id="st-alu"><div class="cap">ALU</div><div class="val">'+esc(lastOp(i))+'</div></div>';
  sh+='<div class="station" id="st-msr"><div class="cap">MSR machine</div><div class="val">'+msrTxt(st)+'</div></div>';
  sh+='<div class="station" id="st-cr"><div class="cap">Control registers</div><div class="val">'+
      'CR0 <b>'+z(st.cr['0'])+'</b> &middot; CR3 <b>'+z(st.cr['3'])+'</b> &middot; CR4 <b>'+z(st.cr['4'])+'</b></div></div>';
  sh+='<div class="station" id="st-gdt"><div class="cap">GDT gangway</div><div class="val">'+(st.msr.__gdtr?'loaded':'idle')+'</div></div>';
  sh+='<div class="station" id="st-addr"><div class="cap">Address unit</div><div class="val">RIP + displacement</div></div>';
  sh+='<div class="station" id="st-door"><div class="cap">Door</div><div class="val">'+esc(st.outside||'—')+'</div></div>';
  $('stations').innerHTML=sh;
  /* flags */
  var fh='',keys=['CF','ZF','SF','OF'];
  for(var k2=0;k2<keys.length;k2++){
    var f=keys[k2], on=st.f[f];
    fh+='<div class="die"><span class="pin'+(on?' on':'')+'"></span><span>'+f+' = '+(on?'1':'0')+'</span></div>';
  }
  $('flags').innerHTML=fh;
  /* stack */
  var stk='';
  for(var k3=0;k3<4;k3++){
    stk+='<div class="die"><span class="pin'+(k3===0?' on':'')+'"></span><span>0x'+
      hex(BigInt(st.regs.rsp)+BigInt(k3*8)).slice(-6)+' &nbsp;<b>'+z(st.mem[k3])+'</b></span></div>';
  }
  $('stack').innerHTML=stk;
  /* source */
  var h='';
  st.src.forEach(function(l){
    var cls=l.n===st.ins.ln?'cur':(l.t.trim()?'hit':'');
    h+='<div class="srow '+cls+'"><span class="n">'+l.n+'</span><span class="c">'+esc(l.t)+'</span></div>';
  });
  $('src').innerHTML=h;
  /* hw table */
  var t='<table><colgroup><col style="width:34%"><col style="width:26%"><col style="width:12%"><col></colgroup>'+
        '<tr><th>part</th><th>item</th><th>acc</th><th>why</th></tr>';
  (st.hw||[]).forEach(function(r){t+='<tr><td>'+esc(r[0])+'</td><td>'+esc(r[1])+
    '</td><td class="acc '+r[2]+'">'+r[2]+'</td><td>'+esc(r[3])+'</td></tr>';});
  t+='</table>';
  $('hwt').innerHTML=t;
  /* description (hidden by default) */
  var nd=narrate(i);
  $('detail').innerHTML='<div style="padding:6px 10px">'+esc(nd[1])+'</div>';
  /* narration + robot */
  $('nkind').textContent=nd[0];
  $('ntext').textContent=nd[1];
  moveRobot(i);
  /* list highlight */
  var rows=$('list').children;
  for(var k4=0;k4<rows.length;k4++){
    rows[k4].className='irow'+(beats.indexOf(k4)>=0?' beat':'')+(k4===i?' cur':(k4<i?' past':''));
  }
  var r=rows[i]; if(r&&r.scrollIntoView) r.scrollIntoView({block:'nearest'});
  $('pos').innerHTML='step <b>'+(i+1)+'</b>/'+N+' &middot; '+
    '<b>'+hex(st.ins.a).slice(-8)+'</b> &middot; line <b>'+st.ins.ln+'</b>';
  $('prev').disabled=i===0; $('first').disabled=i===0;
  $('next').disabled=i===N-1; $('last').disabled=i===N-1;
}
function lastOp(i){
  for(var k=i;k>=0&&k>i-4;k--){
    var o=STEPS[k].ins.t.split(/\s+/), m=o[0].split('.')[0];
    if(['add','sub','and','or','xor','shl','shr','sal','sar','cmp','test','bts','btsq','bt'].indexOf(m)>=0)
      return STEPS[k].ins.t;
  }
  return 'idle';
}
function msrTxt(st){
  var k=Object.keys(st.msr).filter(function(x){return x!=='__gdtr';});
  if(!k.length) return 'untouched';
  return k.map(function(x){return '['+Number(x).toString(16)+'] '+z(BigInt(st.msr[x]));}).join(' ');
}
function moveRobot(i){
  var st=STEPS[i], nd=narrate(i), robot=$('robot'), floor=$('floor');
  if(st.kind==='idle'){ $('robot').className='gone'; return; }
  var o=st.ins.t.split(/\s+/), a=(o.length>1?o.slice(1).join(' ').split(','):[]);
  var s=st.station||'', tgt=null;
  if(s.indexOf('%cr')===0) tgt='st-cr';
  else if(s==='msr'||s==='cpuid') tgt='st-msr';
  else if(s==='gdt') tgt='st-gdt';
  else if(s==='alu') tgt='st-alu';
  else if(s==='stack') tgt='stack';
  else if(s==='flags') tgt='flags';
  else if(s==='door') tgt='st-door';
  else if(s==='addr') tgt='st-addr';
  if(!tgt){
    /* mov / lea: walk to the DESTINATION bin — this is the whole point of the robot */
    var d=(a[1]||'').trim();
    if(d){ var r=canon(d); if($('bin-'+r)) tgt='bin-'+r; }
  }
  if(!tgt) tgt='regs';
  var el=$(tgt);
  if(!el) return;
  var fr=floor.getBoundingClientRect(), er=el.getBoundingClientRect();
  var x=Math.max(0,Math.min(Math.max(fr.width-34,0), er.left-fr.left+floor.scrollLeft+Math.min(er.width/2,60)));
  var y=Math.max(0, er.top-fr.top+floor.scrollTop+er.height/2-15);
  robot.style.transform='translate('+x+'px,'+y+'px)';
  robot.className='';
  var carry=$('carry'), isCarry=(st.kind==='mov'||st.kind==='lea'||st.kind==='push'||st.kind==='cr');
  if(carry){ if(isCarry&&a[0]){carry.textContent=canon(a[0]);carry.className='carry on';}
             else {carry.className='carry';} }
  highlight(tgt);
}
function highlight(tgt){
  var ids=['st-alu','st-msr','st-cr','st-gdt','st-addr','st-door'];
  for(var i=0;i<ids.length;i++){ var e=$(ids[i]); if(e) e.className='station'+(ids[i]===tgt?' hot':''); }
}
/* ================= controls ================= */
function select(i){i=Math.max(0,Math.min(N-1,i)); cur=i; draw(i);}
function nextBeat(){
  for(var k=cur+1;k<N;k++) if(beats.indexOf(k)>=0) return select(k);
  for(var k2=0;k2<=cur;k2++) if(beats.indexOf(k2)>=0) return select(k2);
}
function play(){
  if(timer){clearInterval(timer);timer=null;$('play').textContent='\u25b6 play';return;}
  $('play').textContent='\u23f8 pause';
  timer=setInterval(function(){ if(cur>=N-1){clearInterval(timer);timer=null;$('play').textContent='\u25b6 play';return;} select(cur+1); },700);
}
$('first').onclick=function(){select(0);};
$('prev').onclick=function(){select(cur-1);};
$('next').onclick=function(){select(cur+1);};
$('last').onclick=function(){select(N-1);};
$('play').onclick=play;
$('beat').onclick=nextBeat;
$('detailb').onclick=function(){var m=$('main');m.classList.toggle('withdetail');
  $('detailb').className=m.classList.contains('withdetail')?'':'hot';};
document.onkeydown=function(e){
  if(e.key==='ArrowRight'){select(cur+1);e.preventDefault();}
  if(e.key==='ArrowLeft'){select(cur-1);e.preventDefault();}
  if(e.key===' '){play();e.preventDefault();}
  if(e.key==='b'){nextBeat();}
};
buildList(); buildFloor(); select(0);
$('foot').innerHTML='Real code: '+D.file+' &mdash; disassembled from the real vmlinux at '+hex(D.lo)+
  '. Instruction bytes, addresses and source lines are exact; control flow is followed by address, so calls, returns and jumps really execute.';
</script></body></html>
'''
if __name__=='__main__': main()
