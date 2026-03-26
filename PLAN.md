# PenExecute — Analysis Quality Improvement Plan

This plan addresses the finding quality issues observed in the analysis run against the INT network.
Issues are grouped by root cause and ordered by impact. Each phase is self-contained and can be
implemented independently.

---

## Observed Problems (Summary)

1. **Massive duplication** — 34 findings for a printer, 36 for a 3-port Windows workstation. The
   cross-prompt dedup at 60% Jaccard overlap is too loose; the model rephrases the same finding
   with different wording across prompt passes and they survive dedup.

2. **CVE hallucination** — The model attributed incorrect CVE IDs to findings (e.g. a Zerologon
   CVE on an SMB signing finding, PHP CVEs on an OpenPegasus WBEM service). The pipeline has no
   post-parse validation that a CVE ID is plausible for the product/service it was attached to.

3. **Speculative findings without scan evidence** — Findings for ADCS, WPAD, GPP/SYSVOL,
   AlwaysInstallElevated, BOLA, webhook SSRF, and others were generated with no supporting data
   in the scan JSON. The evidence-quote validation only downgrades confidence to LOW; it does not
   remove the finding.

4. **IoT/consumer device over-analysis** — Chromecast (.136) and Nest Audio (.140) were not
   classified as `smart_speaker` because their hostname/OS fields don't contain the expected
   keywords. They fell through to `unknown` device type, bypassing the IoT finding caps and
   filters.

5. **IPv6 and network-layer findings generated unconditionally** — The network service prompt
   instructs the model to generate IPv6 RA/DHCPv6 findings for any Windows or Linux host, and
   ARP poisoning findings for any LAN host, regardless of whether any IPv6 or layer-2 evidence
   is present in the scan data.

6. **Workstation misclassification** — The Windows 10 workstation (.134) was not classified as
   `workstation` because the OS field is `"Windows"` with version `"10"` in a separate field.
   The classifier only checks `os.contains('windows 10')` against the combined `os` field, not
   `os_version`.

---

## Phase 1 — Fix Device Type Classification

**Files:** `lib/services/vulnerability_analyzer.dart`

**Goal:** Ensure every device is classified correctly so the right finding caps and IoT filters
apply. Misclassification is the root cause of IoT devices receiving server-level analysis.

### ✅ Step 1.1 — Include `os_version` in the classification text

In `_classifyDeviceType()`, the `os` variable is built from `d['device']?['os']` only. The
`os_version` field is not included. The workstation check `os.contains('windows 10')` fails when
the JSON has `"os": "Windows"` and `"os_version": "10"` as separate fields.

Fix: build a combined `osWithVersion` string that concatenates `os` and `os_version` (with a
space), and use that string for all OS-based classification checks.

```
// Before
final os = (d['os'] ?? d['device']?['os'] ?? '').toString().toLowerCase();

// After
final osRaw = (d['os'] ?? d['device']?['os'] ?? '').toString().toLowerCase();
final osVersion = (d['os_version'] ?? d['device']?['os_version'] ?? '').toString().toLowerCase();
final os = '$osRaw $osVersion'.trim();
```

### ✅ Step 1.2 — Add Google Cast / Nest / Android device indicators to smart_speaker classification

The Chromecast and Nest Audio devices have hostnames like `Android_ONXYZ85S.local` and
`Nest-Audio`, and their certificates are issued by `Google Inc` / `Chromecast ICA`. None of these
strings are in the current `smart_speaker` keyword list.

Fix: extend the `smart_speaker` branch in `_classifyDeviceType()` to also match:
- `nest` in hostname or allText
- `chromecast` in allText (already present — verify it's checked against allText not just hostname)
- `google cast` in allText (already present — same check)
- Certificate issuer strings: `chromecast ica` in allText
- Port signature: ports {8008, 8009, 8443, 9000} with no SMB/SSH/FTP and a Google-issued cert
  → classify as `smart_speaker`

### ✅ Step 1.3 — Add Philips Hue to `generic_iot` classification

The Hue Bridge (.154) has `"os": "Philips Hue Bridge"` and `allText` contains `philips hue`.
The current `generic_iot` branch already checks `allText.contains('philips hue')` — verify this
is actually matching. If the device JSON nests the OS under `device.os`, confirm the `allText`
construction includes the nested value (it does via `d.toString()`).

Also add `signify` to the generic_iot keyword list (Philips Hue's parent company name appears in
the firmware's license files and may appear in future scan data).

---

## Phase 2 — Tighten Deduplication

**Files:** `lib/services/vulnerability_analyzer.dart`

**Goal:** Eliminate the semantic duplicates that survive the current dedup passes. The core problem
is that the cross-prompt dedup uses a 60% Jaccard threshold on problem+description word overlap,
but the model generates findings with different titles and slightly different descriptions that
fall just under the threshold.

### ✅ Step 2.1 — Lower the cross-prompt dedup Jaccard threshold

In `_crossPromptDedup()`, the overlap threshold is `> 0.6`. Lower it to `> 0.45`. This is the
single highest-leverage change — it will collapse the majority of the observed duplicates.

The risk of false positives (collapsing genuinely different findings) is low because the grouping
is already scoped by `vulnerabilityType`, so two findings must share the same attack class before
the overlap check runs.

### ✅ Step 2.2 — Add problem-title similarity as a secondary dedup signal

The current `_normalizeForDedup()` takes the first 5 sorted significant words as a fingerprint.
This misses cases where the same concept is expressed with different word order or synonyms (e.g.
"SMB Relay Attack via Enabled but Not Required Signing" vs "SMB Signing Enabled But Not Required
— NTLM Relay Vulnerability").

Fix: after the existing dedup pass, add a second pass that compares problem titles using a
trigram-based similarity score. If two findings in the same `vulnerabilityType` group have a
problem-title trigram similarity above 0.5, keep only the higher-severity one.

Implement a `_trigramSimilarity(String a, String b)` helper:
1. Generate all 3-character substrings of each normalized string
2. Compute Jaccard similarity of the two trigram sets
3. Return the similarity score

This catches title-level duplicates that the word-overlap check misses because the descriptions
differ.

### ✅ Step 2.3 — Tighten the per-target finding cap for workstations

The current `_maxFindingsPerTarget` is 50 for `unknown` device types. A workstation with 3 open
ports should not produce 36 findings. Add a `workstation` cap:

```dart
static const _maxFindingsWorkstation = 20;
```

And add it to the `switch` in `_capFindingsPerTarget()`:
```dart
'workstation' => _maxFindingsWorkstation,
```

---

## Phase 3 — CVE Attribution Validation

**Files:** `lib/services/vulnerability_analyzer.dart`

**Goal:** Prevent the model from attaching a CVE ID to a finding where the CVE's affected product
does not match any product/service observed in the scan data.

### ✅ Step 3.1 — Add a post-parse CVE plausibility check

After parsing findings from the LLM response (in `_parseVulnerabilities()`), add a
`_validateCveAttribution()` pass that runs before the findings are returned.

The check is product-name based, not CVE-ID based (to avoid hardcoding CVE IDs):

For each finding with a non-empty `cve` field:
1. Extract the product tokens from the CVE's associated finding description and problem string
2. Check whether any of those tokens appear in the device JSON (product names, service banners,
   CPE strings)
3. If no product token from the finding matches anything in the device JSON, downgrade the
   finding's confidence to `LOW` and append a note to the evidence field:
   `"[CVE attribution unverified — no matching product observed in scan data]"`

This is intentionally conservative — it does not remove the finding, only flags it. The executor
loop will then have lower priority for it.

### ✅ Step 3.2 — Add a CVE-to-service-port plausibility check

A secondary check: if a finding has a CVE and a specific port in its problem/description, verify
that port is actually open in the device JSON. If the port is not open, downgrade confidence to
`LOW`.

This catches cases like a Zerologon CVE (which requires a domain controller on port 445 with
specific Netlogon behavior) being attached to a workstation that merely has port 445 open.

Implementation: extract port numbers mentioned in the finding's problem and description using a
regex (`\b\d{2,5}\b` filtered to valid port range). Cross-reference against the `open_ports`
array in the device JSON. If a specific port is mentioned but not open, downgrade.

---

## Phase 4 — Speculative Finding Suppression

**Files:** `lib/services/vulnerability_analyzer.dart`, `lib/services/prompt_templates.dart`

**Goal:** Remove findings that have no grounding in the scan data before they reach the UI.
Currently, findings with no evidence quote are only downgraded to LOW confidence — they are not
removed. This phase adds removal logic for the most common speculative finding patterns.

### ✅ Step 4.1 — Remove LOW-confidence findings with no evidence quote for non-IoT devices

The current `_filterIrrelevantFindings()` removes LOW confidence findings only when
`evidence.trim().length < 20`. This is too permissive — the model often writes a plausible-sounding
evidence string that is not actually from the scan data.

Fix: strengthen the removal condition. For non-IoT, non-CVE findings with `confidence == LOW`:
- If `evidence_quote` is empty OR was not found in the device JSON (already tracked by the
  evidence validation pass), remove the finding entirely rather than keeping it at LOW confidence.
- Exception: keep LOW-confidence findings that have a CVE ID (they may still be worth testing).

### ✅ Step 4.2 — Add scan-data presence checks for infrastructure attack findings

Several finding categories are generated speculatively based on OS type alone, with no direct
scan evidence. Add explicit presence checks in `_filterIrrelevantFindings()` for:

**LLMNR/NBT-NS poisoning:** Only generate if the device JSON contains evidence of Windows
broadcast name resolution being active (e.g. NetBIOS name in nmap scripts, port 137/138/139
open, or explicit LLMNR reference in scan output). A Windows OS alone is not sufficient.

**IPv6 RA / DHCPv6 rogue server:** Only generate if the device JSON contains an IPv6 address,
an IPv6-related service, or explicit dual-stack indicators. The current network service prompt
instructs the model to generate these for any Windows/Linux host — add a filter that removes
them when no IPv6 evidence is present in the device JSON.

**ARP poisoning / MITM:** This is a generic network-layer attack applicable to every LAN host.
It provides no actionable pentest value as a standalone finding. Remove ARP poisoning findings
entirely unless the device JSON contains evidence of a specific protocol that makes MITM
particularly impactful (e.g. cleartext Telnet or FTP already generates its own finding).

**GPP/SYSVOL credential exposure:** Only generate if SYSVOL or NETLOGON share access was
confirmed in the SMB findings, or if the device is confirmed as a domain controller. A Windows
workstation with SMB open is not sufficient evidence.

**ADCS web enrollment:** Only generate if port 80 or 443 is open AND the web findings contain
evidence of an IIS-hosted certificate enrollment page (e.g. `/certsrv` path, `CertSrv` in
response body, or explicit ADCS indicator in scan data).

**AlwaysInstallElevated:** Only generate if registry query output or explicit policy evidence
is present in the scan data. This is a post-exploitation finding that cannot be assessed from
network scan data alone.

Implementation: add a `_hasEvidence(String deviceJson, List<String> indicators)` helper that
returns true if any of the indicator strings appear in the device JSON. Use this in
`_filterIrrelevantFindings()` for each category above.

### ✅ Step 4.3 — Strengthen the network service prompt's IPv6 instruction

In `networkServiceAnalysisPrompt()` in `prompt_templates.dart`, the IPv6 section currently
instructs the model to generate IPv6 findings for "any Windows or Linux hosts present." This is
the direct cause of unconditional IPv6 findings.

Change the instruction to require direct IPv6 evidence:

```
Generate IPv6 findings ONLY when IPv6 addresses, IPv6 services, or dual-stack indicators are
directly observed in the scan data. Do NOT generate IPv6 findings based solely on the OS type.
If no IPv6 evidence is present, return an empty array for this section.
```

Similarly, remove the instruction to generate DHCPv6 findings for "any Windows or Linux hosts
present" — replace with "only when DHCPv6 service indicators or IPv6 addresses are observed."

---

## Phase 5 — Prompt-Level Anti-Hallucination Guardrails

**Files:** `lib/services/prompt_templates.dart`

**Goal:** Add explicit instructions to the output format block and CVE analysis prompt that
reduce the model's tendency to fabricate CVE IDs and generate findings for unobserved services.

### ✅ Step 5.1 — Add a CVE attribution rule to `_outputFormatBlock()`

Add the following rule to the `_outputFormatBlock()` string, immediately after the existing
`EVIDENCE RULE`:

```
CVE ATTRIBUTION RULE: A CVE ID in the "cve" field MUST correspond to a vulnerability in the
exact product identified in the scan data. Do NOT assign a CVE to a finding if the CVE's
affected product does not match the observed product name or service banner. If you are uncertain
whether a CVE applies to the observed product, leave the "cve" field empty and describe the
vulnerability class in the description instead. A wrong CVE is worse than no CVE.
```

### ✅ Step 5.2 — Add a service-grounding rule to `_outputFormatBlock()`

Add the following rule:

```
SERVICE GROUNDING RULE: Every finding must be grounded in a service or endpoint that is directly
observed in the device data above. Do NOT generate findings for services, ports, or technologies
that are not present in the open_ports, web_findings, nmap_scripts, or other_findings sections.
Theoretical attack paths that require infrastructure not observed in the scan data must be rated
LOW confidence and must clearly state what additional evidence would be needed to confirm them.
```

### ✅ Step 5.3 — Add a deduplication instruction to `_outputFormatBlock()`

The model generates multiple findings for the same root vulnerability across different prompt
passes. Add an instruction to reduce this at the source:

```
DEDUPLICATION RULE: Each distinct vulnerability should appear ONCE in your output. Do not emit
multiple findings that describe the same attack (e.g. do not emit both "SMB Relay Attack" and
"NTLM Relay via SMB Signing Not Required" — pick the most precise description and emit it once).
If a finding has multiple exploitation paths, describe them all within a single finding's
description field rather than creating separate findings.
```

---

## Phase 6 — Evidence Validation Strengthening

**Files:** `lib/services/vulnerability_analyzer.dart`

**Goal:** The current evidence validation downgrades confidence when the `evidence_quote` is not
found in the device JSON. This is correct but incomplete — the model often omits the
`evidence_quote` field entirely (leaving it empty) while still claiming HIGH confidence. An empty
evidence quote currently passes validation unchanged.

### ✅ Step 6.1 — Treat missing evidence quote as a confidence downgrade trigger

In `_validateEvidenceQuotes()`, the current logic skips validation when `quote.isEmpty`. Change
this: if `evidence_quote` is empty AND the finding has `confidence == HIGH` or `MEDIUM`, downgrade
to `LOW` unless the finding has a CVE ID (CVE-backed findings may be valid even without a direct
quote).

```dart
// Current: if (quote.isEmpty || quote.length < 8) return v;
// New:
if (quote.isEmpty || quote.length < 8) {
  if (v.cve.isEmpty && v.confidence.toUpperCase() != 'LOW') {
    return _copyWithConfidence(v, 'LOW');
  }
  return v;
}
```

### ✅ Step 6.2 — Add a minimum evidence string length check

The `_filterIrrelevantFindings()` check `v.evidence.trim().length < 20` is the threshold for
removing speculative LOW-confidence findings. This is too short — a 20-character evidence string
can be a generic phrase like "SMB port 445 is open" that doesn't actually quote scan data.

Raise the threshold to 40 characters. This removes findings where the evidence field is a
generic placeholder rather than actual scan output.

---

## Phase 7 — AJP / Ghostcat False Positive Prevention

**Files:** `lib/services/vulnerability_analyzer.dart`

**Goal:** The Ghostcat (CVE-2020-1938) false positive on Google Cast devices occurs because nmap
labels port 8009 as `ssl/ajp13?` (with a question mark indicating uncertainty). The model treats
the uncertain service identification as definitive.

### ✅ Step 7.1 — Extend the IoT technology filter for AJP/Ghostcat

The `_filterIrrelevantFindings()` already filters `tomcat`, `ajp`, and `ghostcat` mentions for
IoT device types. Verify this filter is applied to `smart_speaker` — it is, since `smart_speaker`
is in the IoT device type set. The issue is that .136 and .140 were classified as `unknown` (see
Phase 1). Fixing Phase 1 will fix this automatically.

### ✅ Step 7.2 — Add a service-certainty check for AJP findings

As a belt-and-suspenders fix independent of device classification: in `_filterIrrelevantFindings()`,
add a check that removes AJP/Ghostcat findings when the service identification in the device JSON
contains a question mark (indicating nmap uncertainty). Check the `service`, `extra_info`, and
`banner` fields of the relevant port for a `?` suffix.

```dart
// Remove AJP/Ghostcat findings when the service identification is uncertain
if (_mentionsTechnology(text, 'ajp') || _mentionsTechnology(text, 'ghostcat')) {
  // Check if the AJP service identification in the device JSON is uncertain
  if (_isServiceIdentificationUncertain(deviceJson, 8009)) return false;
}
```

Implement `_isServiceIdentificationUncertain(String deviceJson, int port)` to check whether the
port's `service`, `extra_info`, or `banner` field ends with `?`.

---

## Phase 8 — Printer-Specific Finding Consolidation

**Files:** `lib/services/prompt_templates.dart`

**Goal:** The printer (.186) generated 34 findings, mostly duplicates of anonymous FTP, Telnet,
and SHA-1 certificate findings. The printer prompt fires alongside the general web, network, and
SSL prompts, causing the same findings to be generated multiple times.

### ✅ Step 8.1 — Add a deduplication instruction to the printer prompt

In the printer/MFP analysis prompt (`printerMfpAnalysisPrompt()`), add an explicit instruction:

```
SCOPE RESTRICTION: Only generate findings for vulnerabilities that are SPECIFIC to printer/MFP
devices and not already covered by the general network service analysis (FTP, Telnet, SSL/TLS).
Do NOT re-generate findings for anonymous FTP, cleartext Telnet, or weak TLS certificates —
those are handled by other analysis passes. Focus on printer-specific attack surfaces: web admin
interface default credentials, print job interception, SNMP community strings, PJL/PostScript
command injection, firmware update mechanisms, and scan-to-email credential exposure.
```

This reduces the overlap between the printer prompt and the general network/SSL prompts.

---

## Implementation Order

The phases above are ordered by impact-to-effort ratio:

| Priority | Phase | Impact | Effort |
|----------|-------|--------|--------|
| 1 | Phase 1 (device classification) ✅ | High — fixes IoT over-analysis and Ghostcat FP | Low |
| 2 | Phase 2.1 (lower Jaccard threshold) ✅ | High — collapses most duplicates | Trivial |
| 3 | Phase 4.3 (IPv6 prompt fix) ✅ | High — removes unconditional IPv6 findings | Low |
| 4 | Phase 5 (prompt guardrails) ✅ | Medium — reduces hallucination at source | Low |
| 5 | Phase 6 (evidence validation) ✅ | Medium — removes more speculative findings | Low |
| 6 | Phase 2.2 (trigram title dedup) ✅ | Medium — catches remaining title duplicates | Medium |
| 7 | Phase 3 (CVE validation) ✅ | Medium — flags misattributed CVEs | Medium |
| 8 | Phase 4.1–4.2 (speculative removal) ✅ | Medium — removes infrastructure speculation | Medium |
| 9 | Phase 2.3 (workstation cap) ✅ | Low — belt-and-suspenders after classification fix | Trivial |
| 10 | Phase 7.2 (AJP uncertainty check) ✅ | Low — belt-and-suspenders after classification fix | Low |
| 11 | Phase 8 (printer prompt) ✅ | Low — reduces printer duplicates at source | Low |
