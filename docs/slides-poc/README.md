# Interactive Thesis Slide PoC

This is a dependency-free proof-of-concept slide deck for explaining the CHERI
eBPF JIT work visually.

The presentation style and interactive format are the main point of this PoC.
The exact slide content is provisional and should be rewritten before thesis
submission or final presentation use.

Open:

```text
docs/slides-poc/index.html
```

The deck supports:

- left/right arrow navigation;
- previous/next buttons;
- an interactive memory-bounds slide with an offset slider;
- a generated-BPF slide showing the C source shape and emitted eBPF pattern;
- a CVE-style summary slide.

The goal is to make the thesis argument understandable without relying only on
terminal output:

```text
portable eBPF bytecode
  -> target-specific JIT backend
  -> CHERI capability bounds change unsafe failures into traps/rejects/mitigations
```

This is intentionally static HTML/CSS/JS so it can be opened locally during a
presentation without network access or a dev server.
