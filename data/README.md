# Datasets

## vulnerabilities.csv (VulnSage)

`vulnerabilities.csv` is the VulnSage dataset, unchanged, from
https://github.com/Erroristotle/VulnSage (directory `vulnerability_dataset/database/`).

It was created by Arastoo Zibaeirad and Marco Vieira (University of North Carolina at
Charlotte) for the paper *Reasoning with LLMs for Zero-Shot Vulnerability Detection*
(arXiv:2503.17885, 2025) and is distributed under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).

It contains 593 real vulnerabilities (491 CVEs, 52 CWE categories, 2002 to 2019) from the
Linux kernel, Mozilla and Xen. Each row has the vulnerable code block, the patched code
block, the fixing commit, and a noise estimate for how much of the patch is unrelated to
the security fix.

BreachMark reads this file on first start and keeps a copy in its SQLite database. You can
point it at another CSV with the same columns by setting `BREACHMARK_DATASET`.

## sven/ (SVEN)

The `data_train_val` files from https://github.com/eth-sri/sven, MIT License, SRI Lab, ETH Zurich. 803
vulnerable/fixed function pairs in C/C++ and Python over nine CWEs. See `sven/README.md` for details and citation.
Imported automatically on first start as dataset `sven`.

## PrimeVul (not bundled)

Download the `*_paired.jsonl` files from https://github.com/DLVulDet/PrimeVul (Google Drive link in its README)
and import with `python -m breachmark import --format primevul <file-or-folder>` or from the Settings page.

If you use this data, cite:

```bibtex
@article{zibaeirad2025reasoning,
  title   = {Reasoning with LLMs for Zero-Shot Vulnerability Detection},
  author  = {Zibaeirad, Arastoo and Vieira, Marco},
  journal = {arXiv preprint arXiv:2503.17885},
  year    = {2025}
}
```
