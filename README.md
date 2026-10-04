# fsvg-linux

**Linux in my language.** The Linux kernel, rewritten in FSVG.

[FSVG](https://github.com/ArslanCS1993/fsvg) is a language where a program is a
flowchart: boxes are statements, rhombuses are tests, and the edges are control
flow. This repository is the kernel expressed in it — one directory tree per
kernel file, alongside the evidence that each translation is correct.

## Why three panes

Every translated file is shown three ways at once, because a translation is only
worth anything if you can check it:

| Pane | What it is |
|---|---|
| **1. FSVG flowchart** | the code we write — geometry *is* the program |
| **2. Assembly** | what the CPU actually executed, from a real trace |
| **3. Original source** | the kernel's own text, verbatim from the tree |

Click anything in any pane and it highlights in the other two. This is not a
viewer for its own sake: pane 2 is ground truth. Every instruction was recorded
by running the real kernel on real hardware, so a translation can be compared
against what the CPU did rather than merely asserted to be right.

Start here: **[`kernel/arch/x86/entry/entry_SYSCALL_64.html`](kernel/arch/x86/entry/entry_SYSCALL_64.html)**

## What it reveals immediately

The first file translated is `arch/x86/entry/entry_64.S` — the code the CPU
executes first when userspace makes a syscall. Forty-one real instructions map
onto thirteen source lines.

The mapping is not one-to-one, and that is the point. **Line 109 is one source
line that expands to 28 instructions:**

```asm
PUSH_AND_CLEAR_REGS rax=$-ENOSYS
```

Click it and all 28 light up. Kernel work is mostly macro expansion, so a
flowchart that claimed a box per source line would be fiction.

## Honest status

The flowchart for this file is **annotated, not yet compiling.** The header of
each page states how many shapes need ops the compiler does not have yet:

| Missing | Needed for |
|---|---|
| `PUSH` / `POP` | every kernel stack frame |
| `CALL` / `SYSRET` | calls and the fast return path |
| `CLEAR_REGS` | that 28-instruction macro, as one op |
| `SWAPGS` | privileged; cannot run in userspace at all |

That last row is the real blocker, and it is not a syntax problem. FSVG currently
emits Linux **userspace** ELFs. Kernel code needs ring 0, identity-mapped page
tables, a fixed load address and no libc. Until FSVG has a bare-metal target,
these pages are a precise specification of the work, not a running kernel.

## Layout

    kernel/arch/x86/entry/   translated kernel files, one .html per file
    tools/three-pane.py      builds the three-pane page

## Building a page

Needs the unpacked `linux-source` tree and a `trace.json` from the
[cpu-3d](https://github.com/ArslanCS1993/cpu-3d) viewer:

    ./build.sh
    python3 tools/three-pane.py \
        --trace  /path/to/trace.json \
        --kernel /path/to/linux-source-6.8.0 \
        --entry  arch/x86/entry/entry_64.S \
        --out    kernel/arch/x86/entry/entry_SYSCALL_64.html

Output is one self-contained HTML file — no external requests, so it works from
`file://` and offline.