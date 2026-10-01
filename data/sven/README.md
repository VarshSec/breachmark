# SVEN dataset (data_train_val)

Copied unchanged from https://github.com/eth-sri/sven (directory `data_train_val`), MIT License,
Copyright (c) 2024 SRI Lab, ETH Zurich. See LICENSE.txt in this folder.

803 vulnerable/fixed function pairs over nine CWEs (CWE-022, 078, 079, 089, 125, 190, 416, 476, 787)
in C/C++ and Python, curated for the paper *Large Language Models for Code: Security Hardening and
Adversarial Testing* (He & Vechev, CCS 2023, arXiv:2302.05319), from CrossVul, BigVul and VUDENC.
`func_src_before` is the vulnerable function, `func_src_after` the fixed one.

BreachMark imports both `train/` and `val/` as one dataset named `sven` (the split is irrelevant for
zero-shot evaluation). Cite:

```bibtex
@inproceedings{he2023sven,
  title     = {Large Language Models for Code: Security Hardening and Adversarial Testing},
  author    = {He, Jingxuan and Vechev, Martin},
  booktitle = {ACM CCS},
  year      = {2023}
}
```
