# BreachMark, explained simply

## The one-sentence version

BreachMark is an exam for AI models, to see which ones can actually spot security bugs in code.

## The problem

AI chatbots can read computer code. Lots of people now ask them "is this code safe?" and trust the answer. But nobody really knows how good the answer is. The AI sounds confident whether it's right or wrong.

## The idea

If you want to know whether a student is good at spotting mistakes, you give them a test with known answers. BreachMark does that for AI models.

The test questions are **about 1,400 real security bugs** found in real open-source software: the Linux operating system, the Firefox browser, Xen (used in cloud servers), and hundreds of smaller C and Python projects. For each bug we have two pieces of code:

- the **broken** version, with the bug in it
- the **fixed** version, after the developers repaired it

The AI gets shown both and asked the same question each time: *"Does this code have a security bug?"*

- For the broken version, the right answer is **YES**.
- For the fixed version, the right answer is **NO**.

That second part is the clever bit. An AI that panics and says "yes, dangerous!" to everything would look great if you only showed it broken code. Showing it the fixed code too catches the bluffers.

## What you get at the end

A scoreboard. For each AI model you tested, it shows:

- how often it caught a real bug
- how often it wrongly cried wolf on safe code
- how often it dodged the question
- which *kinds* of bugs it is good or bad at (for example: good at memory errors, bad at permission mistakes)

It also lets you compare different ways of asking the question. It turns out "just answer yes or no" gets much worse results than "think it through step by step, then answer". BreachMark measures that difference.

## What it is NOT

It is **not** a tool that finds bugs in *your* code. It's the tool that tells you **how much to trust the AI** that you might use for that. Think of it as the lab that tests smoke detectors, not the smoke detector itself.

(There is one small page, the Playground, where you can paste some code and ask a model about it. That's a convenience, not the main purpose.)

## How you'd use it

1. Install it on a normal laptop (it's small; the heavy lifting is done by the AI model, which can live on your computer or on a server somewhere).
2. Pick a model. Free options exist.
3. Start a run. Go make coffee; it asks the model hundreds of questions and keeps score.
4. Open the dashboard and look at the results.

If you have no AI model at all, there's a "demo" button that runs the whole thing with a pretend model, so you can see how it works. The demo's scores mean nothing; they just show you the screens.

## Why it matters

Companies are starting to let AI review their code for security. If the AI misses half the bugs, that's a problem nobody notices until it's too late. BreachMark gives a number instead of a feeling, so people can decide with their eyes open.

## Where the bugs came from

593 of the bugs were collected by two researchers (Arastoo Zibaeirad and Marco Vieira) for a 2025 study called VulnSage; 803 more come from SVEN, a 2023 ETH Zurich study by Jingxuan He and Martin Vechev. Both teams shared their data openly. BreachMark uses it with credit and builds a tool around it so anyone can repeat and extend their experiments.
