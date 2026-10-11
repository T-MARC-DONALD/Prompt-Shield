# Payload Sources and Provenance

The 55-payload corpus in [`payloads/`](payloads/) contains no improvised strings. Every payload implements an attack technique that is independently documented in peer-reviewed research, security standards, or verified real-world incidents. This document is the source map behind that claim. The corpus schema also records a `source` field on every payload (53 records `manual`, 2 records `community`); see [`schema.md`](schema.md) for the full record format.

## Standards coverage

| Authority | What it establishes |
|---|---|
| OWASP (2025), Top 10 for LLM Applications, LLM01 | Prompt injection ranked the #1 LLM application risk |
| MITRE (2024), ATLAS AML.T0051 | Prompt injection cataloged as an AI threat-matrix technique (direct sub-technique AML.T0051.000) |
| NIST (2024), AI 100-2 | Prompt injection classified in the adversarial machine learning taxonomy |

## Source map by tier

### Tier 1: Direct prompt injection (15 payloads)

| Technique | Payloads | Documented in |
|---|---|---|
| Instruction override | T1-001, T1-003, T1-005, T1-010, T1-011, T1-015 | Perez & Ribeiro (2022), goal hijacking; OWASP (2025); MITRE (2024) |
| System prompt and instruction leakage | T1-002, T1-004, T1-006 to T1-009, T1-012 to T1-014 | Perez & Ribeiro (2022), prompt leaking; Liu et al. (2023); OWASP (2025) |

### Tier 2: Persona hijacking (15 payloads)

| Technique | Payloads | Documented in |
|---|---|---|
| Evil-twin and DAN-style personas | T2-001, T2-005, T2-008, T2-010, T2-015 | Shen et al. (2023); Wei et al. (2023) |
| Fictional framing and roleplay | T2-002, T2-003, T2-007, T2-009, T2-011, T2-013, T2-014 | Liu et al. (2023); Zeng et al. (2024); Wei et al. (2023) |
| Authority impersonation | T2-004, T2-006, T2-012 | Zeng et al. (2024); Liu et al. (2024) |

### Tier 3: Indirect and second-order injection (10 payloads)

| Technique | Payloads | Documented in |
|---|---|---|
| Document and message injection | T3-001 to T3-004, T3-007 to T3-010 | Greshake et al. (2023); Yi et al. (2023), BIPIA; OWASP (2025) |
| Retrieval-style injection | T3-005 | Greshake et al. (2023); Yi et al. (2023) |
| Chained and multi-part injection | T3-006 | Liu et al. (2024); Greshake et al. (2023) |

### Tier 4: Encoding and obfuscation (15 payloads)

| Technique | Payloads | Documented in |
|---|---|---|
| Cipher and interchange encodings (base64, ROT13, reversal, HTML entities, multi-encoding) | T4-001, T4-006, T4-008, T4-012, T4-013, T4-015 | Wei et al. (2023), mismatched generalization; Kang et al. (2023) |
| Character manipulation (leetspeak, token splitting, word separation, word reordering, pig latin, spelling out, variable substitution) | T4-002 to T4-005, T4-009 to T4-011 | Kang et al. (2023); Shen et al. (2023) |
| Unicode smuggling and look-alike characters | T4-007 | Rehberger (2024) |
| Markdown and formatting obfuscation | T4-014 | OWASP (2025) |

## Real-world evidence

- **EchoLeak (CVE-2025-32711):** zero-click indirect prompt injection in Microsoft 365 Copilot capable of exfiltrating sensitive data; documented in Reddy & Gujral (2025).
- Other widely reported incidents: Bing Chat system prompt extraction (2023); Chevrolet dealership chatbot manipulation (2023); Slack AI data exfiltration demonstrations (2024).
- Shen et al. (2023) analyze in-the-wild jailbreak prompts collected from online communities, showing these techniques are produced and shared at scale.

## References

- Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). Not what you've signed up for: Compromising real-world LLM-integrated applications. arXiv. https://arxiv.org/abs/2302.12173
- Kang, D., Li, X., Stoica, I., Guestrin, C., Zaharia, M., & Hashimoto, T. (2023). Exploiting programmatic behavior of LLMs: Dual-use through standard security attacks. arXiv. https://arxiv.org/abs/2302.05733
- Liu, X., Yu, Z., Zhang, Y., Zhang, N., & Xiao, C. (2024). Automatic and universal prompt injection attacks against large language models. arXiv. https://arxiv.org/abs/2403.04957
- Liu, Y., Deng, G., Li, Y., Wang, K., Wang, Z., Wang, X., Zhang, T., & Liu, Y. (2023). Prompt injection attack against LLM-integrated applications. arXiv. https://arxiv.org/abs/2306.05499
- MITRE. (2024). MITRE ATLAS: Adversarial threat landscape for artificial intelligence systems. https://atlas.mitre.org/
- NIST. (2024). Adversarial machine learning: A taxonomy and terminology of attacks and mitigations (NIST AI 100-2). https://csrc.nist.gov/pubs/ai/100/2/e2023/final
- OWASP Foundation. (2025). OWASP Top 10 for large language model applications. https://genai.owasp.org/llm-top-10/
- Perez, F., & Ribeiro, I. (2022). Ignore previous prompt: Attack techniques for language models. arXiv. https://arxiv.org/abs/2211.09527
- Reddy, P., & Gujral, A. S. (2025). EchoLeak: The first real-world zero-click prompt injection exploit in a production LLM system. arXiv. https://arxiv.org/abs/2509.10540
- Rehberger, J. (2024). ASCII smuggling [Blog post]. Embrace The Red. https://embracethered.com/blog/posts/2024/ascii-smuggling/
- Shen, X., Chen, Z., Backes, M., Shen, Y., & Zhang, Y. (2023). "Do Anything Now": Characterizing and evaluating in-the-wild jailbreak prompts on large language models. arXiv. https://arxiv.org/abs/2308.03825
- Wei, A., Haghtalab, N., & Steinhardt, J. (2023). Jailbroken: How does LLM safety training fail? arXiv. https://arxiv.org/abs/2307.02483
- Yi, J., Xie, Y., Zhu, B., Kiciman, E., Sun, G., Xie, X., & Wu, F. (2023). Benchmarking and defending against indirect prompt injection attacks on large language models. arXiv. https://arxiv.org/abs/2312.14197
- Zeng, Y., Lin, H., Zhang, J., Yang, D., Jia, R., & Shi, W. (2024). How Johnny can persuade LLMs to jailbreak them: Rethinking persuasion to challenge AI safety by humanizing LLMs. arXiv. https://arxiv.org/abs/2401.06373
