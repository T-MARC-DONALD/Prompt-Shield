# Document Injection Mitigation Strategies

## Overview
This document outlines three architectural approaches for mitigating document injection and prompt injection attacks across all four PromptShield attack tiers.

**Context:** Following analysis of Tier 3 (document injection) attacks, we propose defense mechanisms that can be:
1. Integrated into PromptShield to measure defense effectiveness
2. Applied to protect real deployed LLM applications
3. Operated in three modes: hard block, transparent mitigation, detection+alerting

**Constraints:**
- Must handle all 4 attack tiers (direct, persona, document injection, encoding)
- Zero-tolerance blocking (aggressive, prefer false positives over false negatives)
- Performance: <100ms overhead per request
- Model-agnostic (work with any LLM API)

---

## Approach 1: Regex + Keyword Filters (Fastest)

### Architecture
Single-pass regex and keyword scanning on input/output:

```
Input Request → Regex/Keyword Scanner → Pass/Block Decision
Response Text → Regex/Keyword Scanner → Pass/Block Decision
```

### Implementation
- 50+ hardcoded regex patterns for injection markers
- Blacklist of instruction keywords ("ignore", "override", "reveal", "bypass")
- Pattern library covering:
  - Direct markers: "INST:", "[INST]", "<!--", "{{", etc.
  - Hidden content: `display:none`, `visibility:hidden`, CSS encoding
  - Instruction keywords in suspicious positions
  - Common encodings: Base64 prefix detection, ROT13 patterns

### Defense Modes
- **Block:** Reject request, return error
- **Sanitize:** Strip detected markers, process cleaned content
- **Alert:** Log and flag for review, continue processing

### Characteristics
| Aspect | Rating |
|--------|--------|
| Performance | ⚡ <10ms |
| Coverage (Tier 1) | ⭐⭐⭐ Excellent |
| Coverage (Tier 2) | ⭐⭐ Good |
| Coverage (Tier 3) | ⭐⭐ Good |
| Coverage (Tier 4) | ⭐ Poor (encoding evasion) |
| False positives | ⭐ High (legitimate multi-turn content) |
| Maintenance | ⭐⭐ Requires constant pattern updates |
| Dependencies | ⭐⭐⭐ Zero (just regex) |

### Pros
- ✅ Extremely fast (<10ms overhead)
- ✅ No external dependencies
- ✅ Fully transparent and auditable
- ✅ Deterministic (reproducible results)

### Cons
- ❌ Brittle — easily evaded with minor modifications
- ❌ High false positive rate on legitimate content
- ❌ Tier 4 encoding attacks slip through
- ❌ Requires constant maintenance

---

## Approach 2: Layered Heuristic Defense (Recommended) ⭐

### Architecture
Three parallel detection layers that run independently, with configurable sensitivity per tier:

```
                        Input Request
                             |
                    ┌────────┼────────┐
                    ↓        ↓        ↓
            Syntax Layer  Semantic  Encoding
             Scanner      Layer     Decoder
                    |        |        |
                    └────────┼────────┘
                             ↓
                    Defense Decision Engine
                    (block/sanitize/alert)
                             ↓
                        Output Decision
```

### Layer 1: Syntax Detection
Identifies structural injection markers without semantic understanding.

**Patterns:**
- XML/HTML injection: `<`, `<!--`, `{{`, `{%`, `[`, `INST`, `-->`
- Hidden content: CSS display/visibility properties, invisible Unicode
- Document markers: `[Turn`, `[INST]`, `[ERROR]`, `<!-- -->`
- Encoded prefixes: `base64:`, `rot13:`, `SWd...` (Base64 detection)

**Output:** List of (position, marker_type, confidence)

### Layer 2: Semantic Detection
Analyzes word sequences for instruction-like patterns in suspicious contexts.

**Instruction keywords:** "ignore", "override", "reveal", "bypass", "execute", "follow", "output", "forget", "disregard"  
**Context clues:** 
- These words appearing near document boundaries
- Appearing in hidden content
- Appearing after structural markers
- Verb+object patterns: "reveal system", "ignore instructions", "output prompt"

**Output:** Instruction pattern matches with confidence scores

### Layer 3: Encoding Detection
Proactively decodes common obfuscations and re-scans for injection patterns.

**Supported encodings:**
- Base64 (standard + variations)
- ROT13
- Text reversal
- Leetspeak / Unicode lookalikes
- HTML entities
- Unicode escapes

**Process:**
```
1. Detect encoding signature (base64 prefix, ROT13 pattern, etc.)
2. Decode to plaintext
3. Re-run Layers 1 & 2 on decoded content
4. Flag if injection pattern found in decoded form
```

**Example:**
```
Input: "aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM="
↓
Detects: Base64 signature
↓
Decodes to: "ignore all previous instructions"
↓
Semantic layer detects: "ignore" + "instructions" = injection pattern
↓
Result: BLOCK (Tier 4 attack detected)
```

### Defense Decision Engine
Combines scores from all three layers:

```python
score = (syntax_score * 0.4) + (semantic_score * 0.4) + (encoding_score * 0.2)

if score >= tier_threshold[tier]:
    action = block | sanitize | alert
```

**Per-tier thresholds:**
- Tier 1 (Direct): 0.60 (aggressive)
- Tier 2 (Persona): 0.65 (aggressive)
- Tier 3 (Document): 0.55 (most aggressive — many false positives acceptable)
- Tier 4 (Encoding): 0.70 (high confidence, avoid decoding false positives)

### Defense Modes
- **Block:** Reject with explanation, log incident
- **Sanitize:** Remove/isolate detected injection markers, process cleaned content, log action
- **Alert:** Flag for review, process normally, send to monitoring system

### Performance
- Syntax scan: ~15ms
- Semantic analysis: ~20ms
- Encoding detection/decode: ~40ms
- Decision engine: ~5ms
- **Total: ~50-80ms**

### Characteristics
| Aspect | Rating |
|--------|--------|
| Performance | ⚡⚡ 50-80ms |
| Coverage (Tier 1) | ⭐⭐⭐ Excellent |
| Coverage (Tier 2) | ⭐⭐⭐ Excellent |
| Coverage (Tier 3) | ⭐⭐⭐ Excellent |
| Coverage (Tier 4) | ⭐⭐⭐ Excellent (decoding) |
| False positives | ⭐⭐ Moderate (tunable) |
| Maintenance | ⭐⭐ Add patterns as new attacks emerge |
| Dependencies | ⭐⭐⭐ Zero (pure Python) |

### Pros
- ✅ Covers all 4 tiers including encoding obfuscation
- ✅ Stays under 100ms budget
- ✅ Tunable per tier
- ✅ Transparent heuristics (auditable)
- ✅ Can sanitize instead of just blocking
- ✅ Deterministic (good for research)
- ✅ No ML/dependencies

### Cons
- ❌ More complex than Approach 1
- ❌ Requires careful threshold tuning
- ❌ False positives still possible on multi-turn conversations
- ❌ Encoding layer may decode legitimate Base64 content

---

## Approach 3: ML-Based Classifier (Most Accurate)

### Architecture
Pre-trained neural text classifier specifically trained to detect injection attempts:

```
Input Request → Pre-trained Classifier → Injection Probability (0-1)
                  + Heuristic Layer        
                       ↓
                  Combined Score
                       ↓
                  Defense Decision
```

### Model
- **Architecture:** Lightweight LSTM or DistilBERT fine-tuned for injection detection
- **Training data:** PromptShield's 55 payloads + synthetically generated variations
- **Output:** Probability [0-1] that input contains injection attempt

### Hybrid Approach
Combine ML classifier with heuristic layer:
- **Heuristics:** Catch obvious attacks (99% accuracy, ~5ms)
- **ML model:** Catch subtle/novel attacks (92% accuracy, 80-95ms)
- **Threshold:** If heuristics score high, block immediately; otherwise use ML

### Performance
- Heuristic pre-filter: ~10ms
- ML inference: 50-80ms (if heuristics don't trigger)
- **Total: 50-95ms**

### Characteristics
| Aspect | Rating |
|--------|--------|
| Performance | ⚡⚡ 50-95ms |
| Coverage (Tier 1) | ⭐⭐⭐ Excellent |
| Coverage (Tier 2) | ⭐⭐⭐ Excellent |
| Coverage (Tier 3) | ⭐⭐⭐ Excellent |
| Coverage (Tier 4) | ⭐⭐⭐ Excellent |
| False positives | ⭐⭐⭐ Low (data-driven) |
| Maintenance | ⭐⭐⭐ Update model periodically |
| Dependencies | ⭐ Requires PyTorch/TensorFlow |

### Pros
- ✅ Highest accuracy across all tiers
- ✅ Learns from data, generalizes better
- ✅ Lower false positive rate
- ✅ Catches novel/subtle attacks

### Cons
- ❌ Adds ML dependency (PyTorch/TensorFlow)
- ❌ Model requires training and periodic updates
- ❌ Non-deterministic (model inference variability)
- ❌ Overkill for deterministic patterns
- ❌ Harder to audit/explain decisions
- ❌ Risk of model poisoning/adversarial examples

---

## Recommendation: Approach 2 ⭐

**We recommend Approach 2 (Layered Heuristic Defense)** as the optimal balance:

### Why Approach 2?
1. **Coverage:** Handles all 4 tiers including Tier 4 encoding attacks
2. **Performance:** 50-80ms stays comfortably under 100ms budget
3. **Research-friendly:** Deterministic, transparent, auditable
4. **Flexibility:** Supports block/sanitize/alert modes
5. **Tuning:** Per-tier thresholds for aggressive Tier 3 defense
6. **Dependencies:** Zero external packages
7. **Maintenance:** Grow pattern library as new attacks emerge

### Why not Approach 1?
- ❌ Tier 4 encoding attacks bypass easily
- ❌ High false positive rate makes "block mode" unusable

### Why not Approach 3?
- ❌ Adds heavy ML dependency (overkill for this task)
- ❌ Non-deterministic (bad for research reproducibility)
- ❌ Requires training data and model maintenance
- ❌ Harder to explain false positives

---

## Implementation Plan (Phase 4 Roadmap)

### Module Structure
```
promptshield/
├── defenses/
│   ├── __init__.py
│   ├── sanitizer.py           # Input sanitization
│   ├── validator.py           # Output validation
│   ├── patterns.py            # Regex & keyword patterns
│   ├── semantic.py            # Semantic layer
│   ├── encoding.py            # Encoding detection/decode
│   └── config.py              # Thresholds & settings
│
├── classifier.py              # (existing, updated to use defenses)
└── runner.py                  # (existing, updated to accept --defense flag)
```

### Integration Points
1. **runner.py:** Add `--defense` flag to enable defense modes
2. **classifier.py:** Update to use defense scores in classification
3. **dashboard.html:** Add defense effectiveness metrics page
4. **results table:** Add `defense_action` column (block/sanitize/alert)

### Testing Strategy
- Test each defense layer independently
- Test encoding detection/decode accuracy
- Measure false positive rate on legitimate multi-turn conversations
- Benchmark performance against 100ms target
- Verify all 55 payloads are caught or properly sanitized

---

## Success Criteria

| Criterion | Target | Method |
|-----------|--------|--------|
| Tier 1-4 coverage | 95%+ | Test all 55 payloads |
| Performance | <100ms | Benchmark on typical hardware |
| False positives | <10% on legitimate content | Test multi-turn conversations |
| Block mode | 100% prevent bypass | Verify no payload succeeds with defense enabled |
| Sanitize mode | 100% safe processing | Verify no injection markers reach LLM |
| Alert mode | 100% logging accuracy | Verify all attacks detected and logged |

---

## Next Steps
1. **Design approval:** Get stakeholder sign-off on Approach 2
2. **Detailed design:** Specify pattern library and semantic rules
3. **Implementation:** Build defenses module with all three modes
4. **Testing:** Validate against all 55 payloads
5. **Integration:** Wire into runner.py and classifier.py
6. **Evaluation:** Measure effectiveness and performance
7. **Documentation:** Update README with defense usage guide

