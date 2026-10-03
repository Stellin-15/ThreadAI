---
description: ThreadAI security audit — threat model, vulnerability checklist and fixes for a path (default the whole repo)
argument-hint: "[path] [quick]"
---

Run a ThreadAI security audit using the `security-audit` skill.

Arguments: `$ARGUMENTS`
- The first argument, if given, is the file or directory to audit. Otherwise audit the current repository.
- If the arguments contain `quick`, do a quick scan (scanner pass plus the riskiest files) and label the report accordingly.

Follow the skill's workflow and safety rules exactly. Produce the report in the template format, then stop and ask which findings to fix. Do not edit any files before the user answers.
