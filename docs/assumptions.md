# FAIR-lite assumptions

Every constant in [`app/scoring/fair_lite.py`](../app/scoring/fair_lite.py), with the reasoning behind
it. The section numbers (A1–A7) match the comments in the code. **If you change a constant, update its
entry here in the same commit.**

Some of these values are published standards (A1). Most are modeling judgments (A3–A5). The difference
matters in an interview: say which is which.

## Model shape

```
ALE = LEF × LM                                     dollars / year
LEF = TEF × P(exploit)                             loss events / year
LM  = primary_loss + secondary_loss                dollars / loss event
```

Multiplied, not added: LEF is a *rate* (events per year) and LM is a *cost per event*, so their product
has units of dollars per year. Adding them would sum two different units.

A **scenario** is one CVE on one asset. It is scored only if the asset's declared technology stack is
affected by the CVE (A6). Scenarios are then combined per asset (A7).

---

## A1. CVSS v3.1 weights (a published standard, not our assumption)

| Metric | Values |
|---|---|
| Attack Vector | N 0.85 · A 0.62 · L 0.55 · P 0.20 |
| Attack Complexity | L 0.77 · H 0.44 |
| Privileges Required (scope unchanged) | N 0.85 · L 0.62 · H 0.27 |
| Privileges Required (scope changed) | N 0.85 · L 0.68 · H 0.50 |
| User Interaction | N 0.85 · R 0.62 |
| C / I / A impact | H 0.56 · L 0.22 · N 0 |

- **Exploitability** = 8.22 × AV × AC × PR × UI, divided by its maximum (3.887) to give a 0–1 scale.
- **Impact Sub-Score (ISS)** = 1 − (1−C)(1−I)(1−A), range 0–0.915.

Source: FIRST, *Common Vulnerability Scoring System v3.1: Specification Document*, §7.

**Why reuse CVSS internals instead of the base score?** The base score blends exploitability and impact
into one number. FAIR needs them apart: exploitability feeds *frequency* (LEF), impact feeds *magnitude*
(LM).

## A2. Translating CVSS v2 and v4 onto v3

Old KEV entries often have only a v2 vector, and new CVEs increasingly ship v4 only. Dropping them would
bias the model toward mid-age CVEs.

| v2 | → v3 | Reason |
|---|---|---|
| AC: L / M / H | L / H / H | v3 has no "medium"; medium complexity is not "low" |
| Au: N / S / M | PR: N / L / H | authentication needed ≈ privileges needed |
| C/I/A: N / P / C | N / L / H | Partial ≈ Low, Complete ≈ High |
| (no UI metric) | UI: N | conservative: assume no interaction needed |

| v4 | → v3 | Reason |
|---|---|---|
| AC:H **or** AT:P | AC: H | v4 split complexity into two metrics; either makes the attack harder |
| UI: P / A | UI: R | both mean a user must act |
| VC / VI / VA | C / I / A | impact on the vulnerable system itself |
| (no scope) | unchanged | v4 replaced scope with subsequent-system metrics, which are not modeled |

**Limitation:** this is an approximation. v2 and v4 scores are not numerically equivalent to v3.

## A3. Exploit probability: FAIR "Vulnerability"

```
P(exploit) = exploitability × 0.10           not in KEV
P(exploit) = exploitability × 0.10 × 6       in CISA KEV
```

- **`NON_KEV_EXPLOIT_SCALE = 0.10`.** Only a small minority of published CVEs are ever observed exploited
  in the wild. Research behind FIRST's Exploit Prediction Scoring System (EPSS) (Jacobs et al.) and
  Cyentia/Kenna's *Prioritization to Prediction* series put it on the order of 5%. A 10% ceiling for the
  most exploitable non-KEV CVE sits above that base rate, leaning conservative. *Verify the exact figure
  in the source before quoting it.*
- **`KEV_MULTIPLIER = 6`.** KEV membership is direct evidence of real-world exploitation, which is a
  different kind of signal from CVSS's theoretical severity. The ×6 lifts a maximally exploitable KEV
  CVE to 60%. It stays below 100% because a threat event can still fail: an unusual configuration, a
  WAF rule, or a failed payload.
- `min(p, 1.0)` is only an invariant guard. With these constants the maximum is 0.60.

**Better alternative, not yet used:** EPSS publishes a daily, empirically calibrated exploitation
probability per CVE. Replacing A3 with EPSS would be a strong upgrade.

## A4. Threat event frequency (TEF) per asset type

Attempts per year to exploit **one specific vulnerability** on **one asset**.

| Asset type | TEF | Reasoning |
|---|---:|---|
| `web_app` | 0.80 | Public and indexed. Internet-wide scanners probe it continuously. |
| `api` | 0.60 | Public, but attackers need to know the endpoints. |
| `infrastructure` | 0.40 | Partly exposed (VPN gateways, CI webhooks). |
| `internal_tool` | 0.25 | Attacker needs an internal foothold first. |
| `database` | 0.15 | Should never be directly internet-reachable. Usually hit second-stage. |
| any other | 0.25 | Treated like an internal tool. |

- **`RANSOMWARE_TEF_MULTIPLIER = 1.5`.** CISA's `knownRansomwareCampaignUse = Known` means commodity
  crews have weaponized the CVE and mass-scan for it. That raises how often it is *attempted*, so the
  multiplier goes on TEF, not on P(exploit).

**These are the least grounded numbers in the model.** They set the *relative* exposure between asset
types sensibly, but their absolute level is a judgment. A real engagement would calibrate them from the
organization's own incident history or firewall/IDS logs.

## A5. Loss magnitude

**Benchmark: `BREACH_COST_BENCHMARK = $4,880,000`.** This is the global average total cost of a data
breach in IBM Security / Ponemon Institute, *Cost of a Data Breach Report 2024*. It is used because it
is the most widely cited public figure. *Check the current edition before presenting. Industry-specific
figures (financial services runs well above the global average) would fit a specific organization
better.*

**Primary vs secondary split: 60% / 40%.** The IBM report breaks cost into four categories. Mapped onto
FAIR's two loss types:

| IBM category | FAIR loss type |
|---|---|
| Detection & escalation | Primary (response) |
| Post-breach response | Primary (response, replacement) |
| Lost business | Secondary (reputation, customer churn) |
| Notification | Secondary (stakeholder obligations) |

The primary categories are roughly 60% of the total in that report, the secondary roughly 40%. *Verify
this split against the edition you cite.*

**Primary loss band, from the Impact Sub-Score (A1):**

| ISS | Band | Share of primary pool | $ | Example |
|---|---|---:|---:|---|
| ≥ 0.80 | high | 100% | $2,928,000 | C:H/I:H/A:H, C:H/I:H/A:N |
| 0.50 – 0.80 | medium | 50% | $1,464,000 | C:H alone, L/L/L |
| > 0 – 0.50 | low | 15% | $439,200 | a single L |
| 0 | none | 0 | $0 | |

Bands rather than a continuous function: CVSS impact metrics are only three-level (H/L/N) anyway, and
bands are easier to defend and explain.

**Secondary loss:**

```
secondary = benchmark × 0.40 × (sensitivity_tier / 3) × confidentiality_factor
```

- **Tier / 3.** A tier-3 asset (customer PII, card data) carries the full secondary loss; tier 1
  carries a third. Linear is the simplest defensible choice.
- **Confidentiality factor: H 1.0 · L 0.5 · N 0.2.** Regulatory fines, breach notification and most
  customer churn are triggered by *data exposure*. An integrity- or availability-only incident still
  costs reputation, just less, so it keeps 20%.

**A useful sanity check built into the constants:** a full-CIA-impact breach of a tier-3 asset has
LM = $2,928,000 + $1,952,000 = **$4,880,000**, exactly the benchmark average breach.

## A6. Applicability (which CVEs affect which asset)

Each asset declares its stack as `vendor:product` tokens in NVD CPE naming (`scripts/seed_assets.py`).
A CVE applies if a token matches, by prefix on product, any `vendor:product` in NVD's vulnerable-CPE list
for that CVE, or KEV's vendor/product as a fallback.

- **The seeded stacks are illustrative.** They describe a fictional mid-size fintech. The totals describe
  that fictional company, not any real one.
- An **incomplete** stack under-counts risk. An **over-broad** token (e.g. `microsoft:windows`, which
  prefix-matches hundreds of CVEs) over-counts it.

## A7. Aggregating scenarios into asset-level risk

**The obvious approach is wrong.** Summing every scenario's ALE treats each CVE as a separate,
independent breach. With the live KEV catalog, an asset running Windows Server has 200+ applicable CVEs.
Summing them gives it about 70 expected breaches a year and a nine-figure ALE, which makes no sense.

**What the model does instead: an attacker needs one open door.**

```
asset TEF   = TEF(asset type)                 ×1.5 if any applicable CVE is ransomware-linked
P(any)      = 1 − Π (1 − pᵢ)                  chance at least one applicable CVE is exploitable
asset LEF   = asset TEF × P(any)              capped by how often the asset is attacked at all
asset LM    = Σ pᵢ·LMᵢ / Σ pᵢ                 average loss, weighted toward the easiest doors
asset ALE   = asset LEF × asset LM
```

- With **one** applicable CVE, this reduces exactly to the scenario ALE (tested).
- **P(any)** treats each CVE's exploitability as independent given an attempt. It is a simplification,
  but it only affects how quickly P(any) approaches 1.
- **The LM weighting** reflects attackers taking the path of least resistance.
- **P(≥1 loss event per year) = 1 − e^(−asset LEF)**, treating loss events as a Poisson process.
- **Portfolio total** = sum of asset ALEs. This assumes breaches of *different* assets are independent,
  which ignores lateral movement.

**Remediation figures.** The report shows two numbers per CVE:

| Figure | Meaning |
|---|---|
| Standalone ALE | Sum of that CVE's scenario ALEs, as if it were the only hole. Measures how dangerous the hole is. |
| Reduction if patched alone | Asset ALE minus asset ALE without that CVE. On an asset with many other exploitable CVEs this is near zero. |

A large gap between them is itself a finding: patching one CVE at a time will not reduce that asset's risk.
It needs a systemic fix (upgrade the platform, isolate it, replace it).

## Known limitations (what this model does not know)

1. **Patch state.** Every applicable CVE is assumed unpatched. This is *inherent* risk, not *residual*.
2. **Controls.** No credit for WAFs, EDR, segmentation or MFA.
3. **Uncertainty.** Point estimates only. Stage 8 (Monte Carlo) replaces them with distributions and a
   loss-exceedance curve.
4. **Lateral movement.** Assets are treated as independent. A breach of one does not raise another's risk.
