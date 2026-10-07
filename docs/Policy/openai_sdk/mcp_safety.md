---
policy_id: openai_sdk_mcp_safety
category: openai_sdk
topic: mcp_safety
rules:
  - id: OAI-106
    severity: high
    confidence: 0.9
    scope: agent
    fix_type: config
  - id: OAI-115
    severity: high
    confidence: 0.7
    scope: agent
    fix_type: config
  - id: OAI-116
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: config
references: [LLM01, LLM06]
---

# Policy Rationale: MCP Integration Safety

**Policy ID:** `openai_sdk_mcp_safety`  
**File:** `openai_sdk/mcp_safety.yaml`  
**Rules:** OAI-106, OAI-115, OAI-116  
**Severities:** high, high, high  
**Fix types:** config, config, config  
**References:** LLM01, LLM06

---

## What this policy covers

OpenAI Agents SDK agents that import tools from one or more MCP servers
(`mcp_servers=` present and non-empty — an empty `mcp_servers=[]` wires
nothing and does not fire) but configure no `input_guardrails`. The match is
`agent_kwarg_present: [mcp_servers]` AND NOT `agent_kwarg_list_empty:
[mcp_servers]` AND `agent_kwarg_list_empty:
[input_guardrails]` — it fires only when MCP is actually wired, so non-MCP agents
are unaffected.

OAI-115 and OAI-116 cover the hosted path, where the MCP server is not run by
the agent process at all. The Python `HostedMCPTool(tool_config={...})` and the
TypeScript `hostedMcpTool({...})` hand the named server to the Responses API,
which connects the model to every tool that server advertises. OAI-115 fires
when the Python `tool_config` dict sets no `allowed_tools` (match
`agent_uses_hosted_tool_class: [HostedMCPTool]` AND NOT
`agent_hosted_tool_kwarg_present` for `tool_config.allowed_tools`); OAI-116
fires when the TypeScript options set no `allowedTools`. The allow-list is the
only static narrowing of that catalog, so its absence is the finding.

---

## Why MCP integration is a distinct concern in agent tools

The Model Context Protocol lets an agent import a tool catalog advertised by an
external MCP server. The crucial property is the trust boundary: the tool *names
and descriptions* the model sees are supplied by the MCP server, not the agent
author. Those descriptions are part of the model's prompt — they tell it when and
how to call each tool — so a malicious or compromised MCP server can craft
descriptions that bait the model into harmful actions, exfiltrate data through tool
arguments, or shadow a legitimate tool with a poisoned one. This is the documented
"tool poisoning" / "rug pull" class of MCP attack, and it is a direct instance of
OWASP LLM01 (Prompt Injection): untrusted text from across a trust boundary enters
the model's instruction context.

The agent author cannot review descriptions that are fetched at runtime from a
third party, so the defense has to be an active screen: an `input_guardrail` that
inspects the user input *and* the resolved tool list before the model is invoked.
Without one there is no pre-execution checkpoint between a poisoned MCP catalog and
the model acting on it. The fix is *config* — adding a guardrail to the agent
constructor, not changing any tool's code.

---

## Rule-by-rule defense

### OAI-106 — Agent wires MCP servers without input_guardrails (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** an agent with `mcp_servers=` set and an empty/absent
`input_guardrails`.

**Why it is flaggable:** the agent ingests tool descriptions from an external trust
boundary with no screen between them and the model.

**Real-world consequence:** a compromised MCP server advertises a `read_file` tool
whose description instructs the model to also send file contents to an attacker
endpoint; with no guardrail the model follows it.

**Why severity is high and not medium:** the attack reaches the model's instruction
channel directly and requires only that the MCP server (a separate party) be
malicious or compromised. Not critical because it still depends on the MCP server
being hostile and on a follow-on capability.

**Fix type — config:** add an `input_guardrail` to the agent and pin MCP servers to
known-trusted URLs/checksums.

**Confidence 0.9:** the configuration is read directly — MCP wired, guardrails empty.
The small gap is an agent that screens MCP content through some other mechanism the
rule cannot see.

---

### OAI-115: Agent wires a HostedMCPTool with no allowed_tools allow-list (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** an OpenAI Agents SDK agent (`Agent` or `SandboxAgent`,
Python) whose `tools=[...]` includes a `HostedMCPTool(...)` whose `tool_config`
dict literal has no `allowed_tools` key. The match is
`agent_uses_hosted_tool_class: [HostedMCPTool]` AND NOT
`agent_hosted_tool_kwarg_present` with class `HostedMCPTool` and kwarg
`tool_config.allowed_tools`; the dotted path reads inside the dict literal.

**Why it is flaggable:** a `HostedMCPTool` is not a tool, it is a subscription
to a catalog. The Responses API connects the model to whatever the server at
`server_url` exposes at call time; the agent's source names a server, never
the tools. `allowed_tools` is the one static boundary a reviewer can check,
and without it the surface changes whenever the server is updated, on the far
side of a trust boundary the codebase does not control.

**Real-world consequence:** a server the team adopted for one tool later
exposes another. A documentation server that adds a write-capable tool, or a
compromised server that swaps a tool description for an instruction, reaches
the model as a new capability with no change on the agent side. The
description text is an instruction channel (LLM01) and the tool itself is
capability the agent was never designed to hold (LLM06).

**Why severity is high and not critical:** the boundary is set by a third
party and is unbounded, which is what puts it above medium. It stops short of
critical because the Python path keeps the API's default approval requirement:
a call to an unlisted tool still passes through an approval step unless the
author also set `require_approval` to never. The TypeScript sibling, OAI-116,
explains why that default matters.

**Fix type (config):** add `"allowed_tools": [...]` to the `tool_config` dict,
naming the tools the agent's task needs, and re-review the list when the task
changes. Keep `require_approval` at its default for anything side-effecting.

**Confidence 0.7:** the two facts are read from the constructor literal, so a
fire is not a guess, but the check is presence only. An allow-list that names
every tool counts as present, and a `tool_config` assembled elsewhere (a
variable or a helper) is not enumerable, so the rule fires on it even when the
assembled dict sets the allow-list. That unreadable case is the main false
positive and the reason the number is not higher.

---

### OAI-116: TypeScript agent wires a hostedMcpTool with no allowedTools allow-list (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:** a TypeScript OpenAI Agents SDK `Agent` whose `tools`
array includes a `hostedMcpTool({...})` whose options object sets no
`allowedTools`. The match is `agent_uses_hosted_tool_class: [hostedMcpTool]`
AND NOT `agent_hosted_tool_kwarg_present` with class `hostedMcpTool` and kwarg
`allowedTools`. A `{ toolNames: [...] }` filter object counts as present.

**Why it is flaggable:** the same catalog subscription as OAI-115, with one
sharper edge. `hostedMcpTool()` defaults `requireApproval` to never when the
option is omitted, so an agent that sets neither `allowedTools` nor
`requireApproval` has no static boundary and no runtime approval gate either.
Every tool the server exposes is callable, and every call executes without a
confirmation step.

**Real-world consequence:** a poisoned or newly added tool description reaches
the model unfiltered and the resulting call runs immediately. Where the Python
case leaves an approval prompt between the model and the side effect, this
case leaves nothing, so the first sign of a compromised server is the effect
of the call, not a request to approve it.

**Why severity is high and not critical:** the finding is the absence of a
boundary on a remote catalog, not proof that the catalog holds a dangerous
tool. High reflects that the agent's own author has no way to know what the
boundary contains; critical is reserved for a configuration that removes a
control the codebase demonstrably relies on.

**Fix type (config):** add `allowedTools: [...]` to the `hostedMcpTool({...})`
options, naming the tools the agent may call, and set `requireApproval`
explicitly for anything side-effecting rather than leaving the never default.

**Confidence 0.75:** slightly above OAI-115 because the TypeScript options are
a flat object literal at the call site in the common case, so the presence
check has fewer places to miss than the nested Python dict, and because the
never default means a fire more often describes the real exposure. The same
presence-only limits apply: an allow-list that names everything counts, and an
options object built elsewhere fires even when it sets the list.

---

## What this policy does not cover

- The *quality* of an `input_guardrail` that is present — a no-op guardrail
  satisfies the rule without screening anything.
- The trustworthiness of the MCP server itself (pinning, auth, checksums) — the rule
  checks for the screen, not the server's provenance.
- Tool poisoning that survives the guardrail (a description crafted to pass the
  specific checks the guardrail performs).
- `output_guardrails` gaps for MCP-fetched content (an egress concern; see
  agent_safety OAI-110 for the content-fetch output-guardrail rule).
- The content of an allow-list. OAI-115 and OAI-116 check that `allowed_tools`
  or `allowedTools` is present, not that it is narrow: a list that names every
  tool the server has satisfies them.
- A `tool_config` dict or options object assembled outside the call. The
  predicate reads the literal at the call site, so a boundary set through a
  variable or helper is invisible and the rule fires anyway.
- The Python approval setting. OAI-115 does not read `require_approval`, so an
  agent with an allow-list and `require_approval="never"` is silent.

---

## Recommendations beyond the fix

```python
from agents import Agent, input_guardrail, GuardrailFunctionOutput

@input_guardrail
def screen_mcp(ctx, agent, user_input) -> GuardrailFunctionOutput:
    # Inspect user_input AND the resolved tool list for poisoned descriptions.
    if _looks_poisoned(agent.tools):
        return GuardrailFunctionOutput(tripwire_triggered=True,
                                       output_info="suspicious MCP tool description")
    return GuardrailFunctionOutput(tripwire_triggered=False, output_info="")

agent = Agent(name="research", mcp_servers=[trusted_server],
              input_guardrails=[screen_mcp])
```

1. Add an `input_guardrail` that screens both the user input and the resolved MCP
   tool list before the model runs.
2. Pin MCP servers to known-trusted URLs and verify checksums/signatures where the
   transport allows; treat an unpinned remote MCP server as untrusted input.
3. Pair with `output_guardrails` so data the model tries to send back out through an
   MCP tool argument is inspected before egress.
4. Give every hosted MCP tool an explicit allow-list (`allowed_tools` in the
   Python `tool_config`, `allowedTools` in the TypeScript options) naming only
   the tools the task needs, and set the approval policy explicitly for
   anything side-effecting instead of relying on the SDK default.
