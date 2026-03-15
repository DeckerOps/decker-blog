---
layout: post
title: "Build AI Agents That Work While You Sleep"
date: 2026-03-15
categories: [automation]
excerpt: "The runner is the Python script that actually executes the process. It calls the tools, captures output, makes simple decisions, and hands complex decisions to the AI or the human."
slug: build-ai-agents-that-work-while-you-sleep
author: Decker
---

# Build AI Agents That Work While You Sleep
## Chapter 6: 6. Phase 4 — Build the Runner

## 6. Phase 4 — Build the Runner

The runner is the Python script that actually executes the process. It calls the tools, captures output, makes simple decisions, and hands complex decisions to the AI or the human.

### 6.1 Core architecture

```python
# Every runner has the same basic structure

def setup(target, mode):
    """Create workspace, log engagement start."""

def phase_1(target, eng_dir):
    """Run phase 1 tools, save output, return results."""

def phase_2(target, eng_dir, phase_1_results):
    """Run phase 2 tools, save output, return results."""

# ... more phases

def gate(severity, action, options):
    """Ask human or AI for permission on high-stakes actions."""

def record_finding(severity, title, detail, eng_dir):
    """Save a finding to the report."""

def generate_report(eng_dir):
    """Compile all findings into deliverable."""

def main():
    """Parse args, check auth, dispatch to mode."""
```

### 6.2 The gate() function — most important design decision

The gate controls the autonomy level. Get this right and the agent is useful. Get it wrong and it is either too noisy (asks about everything) or dangerous (does things without asking).

```python
AUTO_SEVERITIES = {"LOW", "INFO", "MEDIUM"}   # Do automatically
ASK_SEVERITIES  = {"HIGH", "CRITICAL"}        # Always ask first

def gate(severity, action, options):
    if severity in AUTO_SEVERITIES:
        return "auto"           # Just do it
    
    if running_in_terminal():
        return console_prompt(action, options)    # Ask on console
    else:
        return telegram_prompt(action, options)   # Ask via Telegram
```

### 6.3 Modes

Every runner should have at minimum three modes:

```
FAST mode    — quick scan, no deep investigation, report at end
FULL mode    — all phases, asks before high-stakes actions
INTERACTIVE  — one phase at a time, decision prompt after each
```

Add domain-specific modes as needed:
```
Pentesting: --mode ad       (Active Directory focused)
            --mode web      (web application only)
            --mode net      (network layer only)
            --mode retest   (re-run previous engagement, delta report)
```

The retest mode is worth calling out specifically. Once you have a finding history, you can run the same target again and produce a delta report showing what was fixed and what remains. This is extremely useful for client follow-up engagements and was not in the original design — it emerged from real use.

### 6.4 Output discipline

Every tool execution should:

```python
# 1. Print to terminal (so you can watch it run)
print(f"  ▸ {tool_name}")

# 2. Save raw output to file
save(raw_dir / f"{tool_name}_output.txt", output)

# 3. Parse for findings
findings = parse_output(output)

# 4. Feed each finding into the investigator queue
for f in findings:
    investigator.enqueue(f)

# 5. Drain the investigator queue (runs all handlers)
investigator.drain()
```

Note the change from version 1: findings are no longer recorded directly. They go into an investigator queue where the dispatch system handles them. This matters and is explained in the next section.

### 6.5 Scope enforcement

Build scope enforcement into the runner from day one, not as an afterthought:

```python
class ScopeEnforcer:
    """
    Enforces authorized scope on every action.
    Supports: exact hostname, subdomain wildcards, CIDR ranges.
    """
    def in_scope(self, target: str) -> bool:
        # Check exact match
        # Check *.domain.com wildcard
        # Check CIDR containment
        # Raise ScopeViolation if out of scope
```

Every probe and every finding generation should pass through scope enforcement. Out-of-scope targets discovered during scanning (via redirects, DNS resolution, lateral discovery) must not be automatically tested.

---
