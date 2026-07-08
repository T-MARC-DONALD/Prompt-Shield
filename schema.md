# PromptShield Payload Library — Schema Reference

## Overview
This library contains 55 attack payloads organized across 4 tiers of LLM prompt injection and jailbreaking techniques.

## File Map
| File | Tier | Technique | Count |
|---|---|---|---|
| tier1_direct.yaml | 1 | Direct Prompt Injection | 15 |
| tier2_persona.yaml | 2 | Persona Hijacking | 15 |
| tier3_indirect.yaml | 3 | Indirect / Second-Order Injection | 10 |
| tier4_encoding.yaml | 4 | Encoding & Obfuscation | 15 |
| **Total** | | | **55** |

---

## Payload ID Convention
```
T{tier}-{number}
T1-001 = Tier 1, payload 001
T4-015 = Tier 4, payload 015
```

---

## Standard Fields (all tiers)

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Unique payload identifier |
| `tier` | int | yes | Attack tier (1–4) |
| `category` | string | yes | Sub-technique within the tier |
| `goal` | string | yes | What a successful attack achieves |
| `prompt` | string | yes | The actual attack string sent to the LLM |
| `success_signals` | list[str] | yes | Keywords indicating attack success in LLM response |
| `severity` | enum | yes | low / medium / high / critical |
| `source` | string | yes | manual / community / research-paper |
| `tags` | list[str] | yes | For filtering and grouping |

## Tier 3 Additional Fields

| Field | Type | Description |
|---|---|---|
| `wrapper` | string | The legitimate user request that wraps the attack |
| `hidden_content` | string | The document/content containing the hidden payload |
| `full_prompt` | string | Complete prompt combining wrapper + hidden content |
| `turns` | list | For multi-turn chained attacks (T3-006) |

## Tier 4 Additional Fields

| Field | Type | Description |
|---|---|---|
| `decoded_payload` | string | The plaintext instruction hidden inside the encoding |

---

## Severity Levels

| Level | Meaning |
|---|---|
| `low` | Attack unlikely to succeed against modern LLMs |
| `medium` | May succeed against some LLMs or weaker system prompts |
| `high` | Succeeds against many LLMs; significant security concern |
| `critical` | High success rate; represents a serious vulnerability |

---

## Goal Taxonomy

| Goal | Description |
|---|---|
| `reveal_system_prompt` | Extract the hidden system/instruction prompt |
| `reveal_rules` | List all restrictions and rules |
| `reveal_restrictions` | Identify what topics are blocked |
| `reveal_full_context` | Dump entire context window |
| `disable_content_filter` | Remove safety guardrails |
| `remove_restrictions` | Operate without guidelines |
| `reset_system_prompt` | Clear all instructions |
| `remove_restrictions_via_persona` | Use identity shift to bypass rules |
| `extract_restricted_info_via_fiction` | Use fictional framing to get restricted content |
| `disable_safety_via_authority` | Claim authority to disable filters |
| `bypass_filter_via_*` | Encoding-based filter bypass |
| `inject_task_via_*` | Replace legitimate task with malicious one |
| `hijack_output_via_*` | Control LLM output through injected content |
| `exfiltrate_context_via_*` | Leak context through a processing task |

---

## Category Taxonomy

### Tier 1
- `instruction_override` — directly override system instructions
- `system_prompt_leak` — extract the system prompt

### Tier 2
- `evil_twin` — create an alter ego with no restrictions
- `fictional_framing` — use fiction/roleplay to bypass rules
- `authority_impersonation` — claim to be developer/admin

### Tier 3
- `document_injection` — hide payload in documents
- `retrieval_injection` — hide payload in web/retrieved content
- `chained_injection` — multi-turn attack

### Tier 4
- `base64` — Base64 encoded instructions
- `rot13` — ROT13 cipher
- `leetspeak` — character number substitution
- `unicode_smuggling` — Unicode lookalike characters
- `token_splitting` — break words to evade token filters
- `reverse_text` — reversed instruction string
- `html_entity` — HTML numeric entity encoding
- `pig_latin` — pig latin encoding
- `markdown_obfuscation` — markdown formatting to hide intent
- `multi_encoding` — layered encoding combination
- `variable_substitution` — use variables to obscure keywords
- `word_reordering` — scrambled word order
- `spelling_out` — letter-by-letter spelling

---

## Usage in Runner

```python
import yaml

def load_payloads(filepath):
    with open(filepath, 'r') as f:
        data = yaml.safe_load(f)
    return data['payloads']

def get_prompt(payload):
    # Tier 3 uses full_prompt field
    return payload.get('full_prompt') or payload.get('prompt')

def check_success(response, payload):
    response_lower = response.lower()
    return any(
        signal.lower() in response_lower
        for signal in payload['success_signals']
    )
```
