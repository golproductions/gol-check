# Check

Check verifies an AI's commands before they run. Before your AI runs a command or writes a file, your own machine checks it: does the program, file, folder, script, package or image it names exist, and does the code parse? When the machine proves the action wrong, Check stops it and tells the AI what the machine said, so it can fix it.

## Install

In Claude Code:

```
/plugin install gol-check --marketplace golproductions/gol-check
```

Other agents (GitHub Copilot, Codex, Cursor, Gemini CLI): https://github.com/golproductions/check-plugins

## What it needs

A GOL API Key from https://golproductions.com/console (14 days free, no card). You enter it when you install the plugin; it is stored in Claude Code's secure storage and never shown to your AI.

## What it runs

- `check-hook.mjs`, the Check client, is the plugin's only code. It runs on each command, file write, message and failed command. It is plain, readable JavaScript, and it never downloads or replaces code: updates come as new versions of this plugin.
- It decides nothing. It tells Check's server what your AI is about to do, and answers the server's questions about your machine, from a fixed list, and only about names the command itself contains.
- To answer, it runs read-only checks: it looks up programs and paths, asks tools such as `git`, `node --check`, `bash -n`, `ruby -c`, `php -l`, `docker image inspect` and PowerShell's parser, and parses files your AI writes. It never runs your command, and never anything that changes your machine.
- It keeps small caches in `~/.check` (routes, Docker help text, PowerShell names, the TypeScript build cache).

## What it sends

To https://triage.golproductions.com: the layout of your AI tool's hook message (field names and lengths, never their values), the command your AI is about to run (credential patterns removed), the working folder (username masked), the results of the machine's checks, and, for a file write, the file's name, size and whether it exists (never its contents). For each message, only its identifier, never its text. It never sends your prompts or your files. The server may look up package and image names on public registries (npm, PyPI, Docker Hub and others). Full details: https://golproductions.com/privacy

## If anything fails

Check never blocks because of its own failure: with no key or no network, actions go ahead unchecked and Check says so.

## Licence

Proprietary. See https://golproductions.com/terms
