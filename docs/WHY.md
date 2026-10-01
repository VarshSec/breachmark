# The problem BreachMark solves

## The situation

Companies and developers are starting to use AI models to review code for security bugs. Some use ChatGPT or Claude directly, some buy tools built on top of them, some run open models on their own servers. Every vendor says their model "finds vulnerabilities". The claim is cheap to make and expensive to check.

Meanwhile, the bugs that matter are not textbook examples. They are a missing bounds check buried in 300 lines of kernel code, a use-after-free that only shows up across two functions, a permission check that was there and then wasn't. Whether a model can find *those* is the only question that counts, and almost nobody measures it.

## Why this is hard to measure yourself

1. **You need real bugs with known answers.** Made-up examples are too easy. Real ones require digging through years of security fixes in big projects and confirming which commit fixed what.
2. **You need the trick question.** If you only show a model buggy code, a model that says "vulnerable" to everything scores 100%. You must also show it the fixed code and check it says "safe". Most informal tests skip this and reach wrong conclusions.
3. **You need volume.** One model, four ways of asking, 593 bugs, two versions each: nearly 5,000 questions. Models time out, crash, give answers that can't be parsed. Doing this by hand, or with a throwaway script, means lost results and numbers you can't reproduce.
4. **You need to read the result properly.** "70% accurate" hides whether the model catches bugs or just avoids false alarms, which bug types it misses, and whether 70% on 40 samples means anything at all.

## What BreachMark does about it

- Ships a curated set of 593 real vulnerabilities from Linux, Mozilla and Xen, with the fixed version of each, from a peer-reviewed study.
- Always asks the trick question: every bug is tested as broken code and as fixed code, and a model gets credit only when it answers both correctly.
- Runs the whole exam automatically against any model you can reach (local through Ollama, or any API), with retries, resumption and a live progress view.
- Reports the numbers that matter: how often the model catches real bugs, how often it raises false alarms on safe code, how often it refuses to commit, with confidence intervals, broken down by bug type.
- Lets you change the question (prompt) and measure the effect, because the way a model is asked changes its score by 20 points or more.
- Keeps every answer, so you can read the model's reasoning on the cases it got wrong.

## Who this is for

- **Security teams** deciding whether to trust an AI review tool, or which model to put behind one.
- **Developers of AI security tools** who need to pick a model and a prompt on evidence, and to re-test when a new model comes out.
- **Researchers and students** who want to reproduce or extend published results on LLM vulnerability detection without rewriting the plumbing.
- **Anyone curious** whether the expensive model is actually better than the free one at this job.

## What it is not

It is not a scanner for your own code. It won't find your bugs; it tells you how good a given model is at finding bugs, so you can decide how much to rely on it. The two are different jobs, and conflating them is how people end up trusting a tool that misses half of what it should catch.

## The honest state of the art

The study this dataset comes from found that open models in 2025 caught roughly half to two-thirds of real bugs when prompted well, and flagged a third of safe code as dangerous. That is useful as a second opinion and dangerous as a sole gate. BreachMark exists so that claim can be re-checked on every new model, by anyone, in an afternoon.
