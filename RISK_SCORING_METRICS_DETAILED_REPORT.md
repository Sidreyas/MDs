# 📊 Risk Scoring Metrics - Detailed Technical Report

**Document Version:** 1.0  
**Last Updated:** December 30, 2025  
**Agents Covered:** Phishing Agent, Login Identity Agent, Exfiltration Agent, Access Control Agent

---

## Table of Contents
1. [Overview](#overview)
2. [Phishing Agent Risk Scoring](#1-phishing-agent-risk-scoring)
3. [Login Identity Agent Risk Scoring](#2-login-identity-agent-risk-scoring)
4. [Exfiltration Agent Risk Scoring](#3-exfiltration-agent-risk-scoring)
5. [Access Control Agent Risk Scoring](#4-access-control-agent-risk-scoring)
6. [Risk Score Comparison Matrix](#risk-score-comparison-matrix)

---

## Overview

### Risk Score Scale
All agents use a standardized **0-100** integer scale:
- **0-20**: Very Low Risk
- **21-40**: Low Risk
- **41-60**: Medium Risk
- **61-80**: High Risk
- **81-100**: Critical Risk

### Common Classification Types
- **TruePositive**: Confirmed malicious activity
- **FalsePositive**: Legitimate activity incorrectly flagged
- **BenignPositive**: Legitimate but unusual activity
- **Undetermined**: Insufficient data for classification

---

## 1. Phishing Agent Risk Scoring

### 📍 Location
**File:** `agents/phishing_agent/graph.py`  
**Function:** `classify_incident()` (lines 540-695)

### Risk Score Definition

The Phishing Agent uses a **rule-based scoring system** with LLM fallback for edge cases.

#### Primary Scoring Formula (Rule-Based)
```python
risk_score = min(95, 70 + (malicious_ips_count + malicious_domains_count) * 10)
```

**Components:**
- **Base Score:** 70 (when any malicious IOC detected)
- **Per Malicious IP:** +10 points
- **Per Malicious Domain:** +10 points
- **Maximum Score:** 95 (capped to leave room for manual escalation)

### Calculation Logic

#### Rule 1: Malicious IOCs Detected (Automatic TruePositive)
```python
if len(malicious_ips) > 0 or len(malicious_domains) > 0:
    classification = 'TruePositive'
    risk_score = min(95, 70 + (len(malicious_ips) + len(malicious_domains)) * 10)
```

**Examples:**
- 1 malicious IP: `risk_score = 70 + 10 = 80`
- 2 malicious IPs: `risk_score = 70 + 20 = 90`
- 3 malicious IPs + 1 domain: `risk_score = 70 + 40 = 95` (capped)

#### Rule 2: LLM-Based Classification (Fallback)
When no clear malicious indicators:
```python
# LLM returns JSON with risk_score
risk_score = llm_result.get('risk_score', 50)  # Default: 50
```

**LLM considers:**
- VirusTotal reputation scores
- AbuseIPDB confidence levels
- DNS/MX/SPF/DMARC validation results
- Blacklist status
- Overall email characteristics

### Factors Affecting Risk Score

| Factor | Impact | Score Change | Detection Method |
|--------|--------|--------------|------------------|
| **Malicious IP (VirusTotal)** | Critical | +10 per IP | `malicious_count >= 2 or suspicious_count >= 5` |
| **Malicious Domain (VirusTotal)** | Critical | +10 per domain | `malicious_count >= 2 or suspicious_count >= 5` |
| **High AbuseIPDB Confidence** | High | Contributes to classification | `confidence >= 75%` |
| **Multiple IOCs** | Escalating | +10 per additional | Additive scoring |
| **Email Validation Failures** | Medium | LLM-determined | SPF/DMARC/DKIM failures |
| **Blacklist Presence** | Medium | LLM-determined | MXToolbox blacklist checks |

### VirusTotal Malicious Threshold
```python
# From tool results analysis
malicious = data.get('malicious', 0)
suspicious = data.get('suspicious', 0)

if malicious >= 2 or suspicious >= 5:
    # Classified as malicious
```

### Classification Decision Tree

```
┌─────────────────────────────────────────┐
│     Phishing Incident Detected          │
└──────────────┬──────────────────────────┘
               │
               ▼
    ┌──────────────────────┐
    │ Extract IOCs         │
    │ (IPs, Domains, etc.) │
    └──────────┬───────────┘
               │
               ▼
    ┌──────────────────────────┐
    │ VirusTotal Check         │
    │ malicious >= 2 OR        │
    │ suspicious >= 5?         │
    └──────┬───────────────────┘
           │
           ├─── YES ──► TruePositive (Risk: 70-95)
           │            Score = 70 + (IOC_count × 10)
           │
           └─── NO ───► LLM Classification
                        │
                        ├─── High confidence ──► TruePositive (Risk: 60-80)
                        ├─── Low confidence ───► FalsePositive (Risk: 10-30)
                        └─── Uncertain ────────► Undetermined (Risk: 40-60)
```

### Risk Score Ranges → Classification Mapping

| Score Range | Classification | Decision |
|-------------|----------------|----------|
| **80-95** | TruePositive | Confirmed malicious - auto-close as malicious |
| **60-79** | TruePositive / Undetermined | Likely malicious - may require review |
| **40-59** | Undetermined | Insufficient data - manual review required |
| **20-39** | FalsePositive / BenignPositive | Likely legitimate - may auto-close as benign |
| **0-19** | FalsePositive | Definitely legitimate - auto-close as benign |

### Code Implementation

**File:** `agents/phishing_agent/graph.py` (lines 590-610)
```python
# CRITICAL DECISION RULE
if len(malicious_ips) > 0 or len(malicious_domains) > 0:
    # AUTOMATIC TRUE POSITIVE
    state['classification'] = 'TruePositive'
    state['risk_score'] = min(95, 70 + (len(malicious_ips) + len(malicious_domains)) * 10)
    
    malicious_list = ', '.join(malicious_ips + malicious_domains)
    state['rationale'] = f"CRITICAL: Detected malicious indicators via VirusTotal. Found {len(malicious_ips)} malicious IP(s) and {len(malicious_domains)} malicious domain(s): {malicious_list}. Per SOC policy, a single malicious IP or domain is sufficient evidence to classify this as a TruePositive phishing incident."
```

---

## 2. Login Identity Agent Risk Scoring

### 📍 Location
**File:** `agents/login_identity_agent/graph.py`  
**Function:** `classify_incident()` (lines 540-650)

### Risk Score Definition

The Login Identity Agent uses a **comprehensive rule-based decision tree** with fixed risk scores per rule.

### Calculation Logic - Rule-Based Decision Tree

#### Rule 0: RDP Whitelist (for RDP incidents)
```python
if rdp_in_whitelist and workflow_type == 'rdp_rare_connection':
    classification = 'FalsePositive'
    risk_score = 5
```
**Rationale:** Pre-approved RDP connection

#### Rule 1: Malicious IP Detected
```python
if len(malicious_ips) > 0:
    classification = 'TruePositive'
    risk_score = min(95, 70 + (len(malicious_ips) * 15))
```
**Formula:**
- Base: 70
- Per malicious IP: +15
- Cap: 95

**Examples:**
- 1 malicious IP: `70 + 15 = 85`
- 2 malicious IPs: `70 + 30 = 95` (capped)

#### Rule 2: High-Risk Region
```python
if high_risk_region:
    classification = 'TruePositive'
    risk_score = 85
```
**High-Risk Regions:** China, Indonesia, Russia, Iran, North Korea, etc.

#### Rule 3: Impossible Travel
```python
if impossible_travel:
    classification = 'TruePositive'
    risk_score = 90
```
**Detection:** User logged in from two geographically distant locations within impossible timeframe

#### Rule 4: Brute Force Attack
```python
if brute_force:
    classification = 'TruePositive'
    risk_score = 80
```
**Threshold:** >5 failed login attempts in short window

#### Rule 5: Approved IP + Correct Location
```python
if ip_in_allowlist and location_matches:
    classification = 'FalsePositive'
    risk_score = 10
```

#### Rule 6: Correct Location + Unapproved IP
```python
if location_matches and not ip_in_allowlist:
    classification = 'BenignPositive'
    risk_score = 35
```
**Scenario:** User on VPN or home network

#### Rule 7: RDP Not Whitelisted
```python
if not rdp_in_whitelist and workflow_type == 'rdp_rare_connection':
    classification = 'TruePositive'
    risk_score = 75
```

#### Rule 8: Location Mismatch (Sign-in)
```python
if not location_matches and not high_risk_region:
    classification = 'Undetermined'
    risk_score = 55
```

#### Rule 9: Insufficient Data
```python
else:
    classification = 'Undetermined'
    risk_score = 40
```

### RDP-Specific Risk Scoring

**File:** `agents/login_identity_agent/tools/rdp_tools.py` (lines 495-565)

#### RDP Anomaly Detection Risk Calculation
```python
risk_score = 0

# Factor 1: Not in whitelist
if not in_whitelist:
    risk_score += 40

# Factor 2: First-time RDP user
if not has_connected_before:
    risk_score += 30
elif total_connections < 5:
    risk_score += 20

# Factor 3: New source IP
if source_ip not in common_ips:
    risk_score += 25

# Risk Level Classification
if risk_score >= 70: risk_level = 'High'
elif risk_score >= 40: risk_level = 'Medium'
else: risk_level = 'Low'
```

### Factors Affecting Risk Score

| Factor | Classification | Risk Score | Condition |
|--------|----------------|------------|-----------|
| **RDP Whitelisted** | FalsePositive | 5 | User-IP in approved list |
| **Malicious IP (1)** | TruePositive | 85 | VirusTotal malicious >= 2 |
| **Malicious IP (2)** | TruePositive | 95 | Multiple malicious IPs |
| **High-Risk Region** | TruePositive | 85 | Login from China/Russia/etc. |
| **Impossible Travel** | TruePositive | 90 | Physically impossible movement |
| **Brute Force** | TruePositive | 80 | >5 failed attempts |
| **Approved IP + Location** | FalsePositive | 10 | Corporate IP + expected country |
| **Correct Location Only** | BenignPositive | 35 | Right country, unapproved IP |
| **RDP Not Whitelisted** | TruePositive | 75 | Rare RDP, not approved |
| **Location Mismatch** | Undetermined | 55 | Wrong location, no other risks |
| **Insufficient Data** | Undetermined | 40 | Cannot determine |

### VirusTotal Malicious Threshold
```python
if malicious >= 2:
    # IP classified as malicious
```

### AbuseIPDB High-Confidence Threshold
```python
if confidence >= 75:
    # High confidence abuse
```

### Classification Decision Tree

```
┌─────────────────────────────────────────┐
│   Sign-in from Unexpected Location      │
└──────────────┬──────────────────────────┘
               │
               ▼
    ┌──────────────────────┐
    │ Check RDP Whitelist  │
    │ (if RDP incident)    │
    └──────┬───────────────┘
           │
           ├─── IN WHITELIST ──► FalsePositive (Risk: 5)
           │
           └─── NOT IN / N/A ──┐
                                │
                                ▼
                    ┌──────────────────────┐
                    │ Check Malicious IPs  │
                    └──────┬───────────────┘
                           │
                           ├─── YES ──► TruePositive (Risk: 85-95)
                           │
                           └─── NO ───┐
                                       │
                                       ▼
                           ┌──────────────────────┐
                           │ Check High-Risk      │
                           │ Region               │
                           └──────┬───────────────┘
                                  │
                                  ├─── YES ──► TruePositive (Risk: 85)
                                  │
                                  └─── NO ───┐
                                              │
                                              ▼
                                  ┌──────────────────────┐
                                  │ Check Impossible     │
                                  │ Travel               │
                                  └──────┬───────────────┘
                                         │
                                         ├─── YES ──► TruePositive (Risk: 90)
                                         │
                                         └─── NO ───┐
                                                     │
                                                     ▼
                                         (Additional checks continue...)
```

### Risk Score Ranges → Classification Mapping

| Score Range | Classification | Decision |
|-------------|----------------|----------|
| **85-95** | TruePositive | Malicious IP/High-risk/Impossible travel |
| **75-84** | TruePositive | Brute force/Unauthorized RDP |
| **50-74** | Undetermined / BenignPositive | Needs review or unusual but safe |
| **30-49** | BenignPositive / Undetermined | VPN/Travel scenario |
| **5-29** | FalsePositive | Legitimate activity |

---

## 3. Exfiltration Agent Risk Scoring

### 📍 Location
**File:** `agents/exfiltration_agent/graph.py`  
**Function:** `classify_incident()` (lines 450-580)

### Risk Score Definition

The Exfiltration Agent combines **malicious IP detection with network transfer volume** for risk calculation.

### Calculation Logic

#### Primary Scoring Formula
```python
risk_score = min(90, 70 + (malicious_ips_count * 10) + int(network_transfer_gb * 5))
```

**Components:**
- **Base Score:** 70 (when malicious IPs detected)
- **Per Malicious IP:** +10 points
- **Network Transfer:** +5 points per GB
- **Maximum Score:** 90 (capped)

### Rule-Based Classification

#### Rule 1: Malicious IP Detected
```python
if len(malicious_ips) > 0:
    classification = 'TruePositive'
    risk_score = min(90, 70 + (len(malicious_ips) * 10) + int(network_transfer_gb * 5))
```

**Examples:**
- 1 malicious IP, 0 GB: `risk_score = 70 + 10 + 0 = 80`
- 1 malicious IP, 2 GB: `risk_score = 70 + 10 + 10 = 90`
- 2 malicious IPs, 1 GB: `risk_score = 70 + 20 + 5 = 90` (capped)

#### Rule 2: Allow-Listed Destinations
```python
if len(allow_listed) > 0:
    classification = 'BenignPositive'
    risk_score = 20
```
**Scenario:** Transfer to approved cloud storage (OneDrive, SharePoint)

#### Rule 3: Suspicious but Unconfirmed
```python
if len(suspicious_ips) > 0:
    classification = 'Undetermined'
    risk_score = 50
```
**Threshold:** AbuseIPDB confidence > 20% but < 75%

#### Rule 4: Insufficient Data
```python
else:
    classification = 'Undetermined'
    risk_score = 40
```

### Factors Affecting Risk Score

| Factor | Impact | Score Calculation | Detection Method |
|--------|--------|-------------------|------------------|
| **Malicious IP** | Critical | Base 70 + 10 per IP | VirusTotal malicious >= 2 |
| **Network Transfer Volume** | High | +5 per GB | Log Analytics query |
| **Multiple Malicious IPs** | Escalating | +10 per additional | Cumulative |
| **High AbuseIPDB Confidence** | Critical | Triggers malicious | confidence >= 75% |
| **Suspicious IPs** | Medium | Fixed 50 | confidence 21-74% |
| **Allow-Listed** | De-escalates | Fixed 20 | Corporate allow-list |

### VirusTotal Thresholds
```python
malicious = data.get('malicious', 0)
suspicious = data.get('suspicious', 0)

if malicious >= 2:
    # Classified as malicious
elif suspicious >= 3:
    # Classified as suspicious
```

### AbuseIPDB Thresholds
```python
confidence = data.get('abuse_confidence_score', 0)

if confidence >= 75:
    # High confidence - malicious
elif confidence > 20:
    # Medium confidence - suspicious
```

### Classification Decision Tree

```
┌─────────────────────────────────────────┐
│     Exfiltration Incident Detected      │
└──────────────┬──────────────────────────┘
               │
               ▼
    ┌──────────────────────┐
    │ Extract IOCs         │
    │ (External IPs,       │
    │  Hosts, Processes)   │
    └──────────┬───────────┘
               │
               ▼
    ┌──────────────────────────┐
    │ Query Network Logs       │
    │ (Transfer volume)        │
    └──────────┬───────────────┘
               │
               ▼
    ┌──────────────────────────┐
    │ Check Malicious IPs      │
    │ (VirusTotal/AbuseIPDB)   │
    └──────┬───────────────────┘
           │
           ├─── MALICIOUS IPs ──► TruePositive
           │                      Risk: 70 + (IPs×10) + (GB×5)
           │                      Cap: 90
           │
           ├─── ALLOW-LISTED ───► BenignPositive (Risk: 20)
           │                      (OneDrive, SharePoint, etc.)
           │
           ├─── SUSPICIOUS IPs ─► Undetermined (Risk: 50)
           │                      Manual review required
           │
           └─── NO INDICATORS ──► Undetermined (Risk: 40)
                                  Insufficient data
```

### Risk Score Ranges → Classification Mapping

| Score Range | Classification | Decision |
|-------------|----------------|----------|
| **80-90** | TruePositive | Confirmed malicious exfiltration |
| **70-79** | TruePositive | Malicious IP with low transfer |
| **50-69** | Undetermined | Suspicious but needs review |
| **40-49** | Undetermined | Insufficient data |
| **20-39** | BenignPositive / FalsePositive | Legitimate transfer |

### Network Transfer Impact Examples

| Malicious IPs | Transfer (GB) | Calculation | Final Score |
|---------------|---------------|-------------|-------------|
| 1 | 0 | 70 + 10 + 0 | 80 |
| 1 | 1 | 70 + 10 + 5 | 85 |
| 1 | 2 | 70 + 10 + 10 | 90 (capped) |
| 1 | 5 | 70 + 10 + 25 | 90 (capped) |
| 2 | 0 | 70 + 20 + 0 | 90 (capped) |
| 2 | 1 | 70 + 20 + 5 | 90 (capped) |

---

## 4. Access Control Agent Risk Scoring

### 📍 Location
**File:** `agents/access_control_agent/graph.py`  
**Function:** `llm_classify()` (lines 260-335)

### Risk Score Definition

The Access Control Agent uses **LLM-based classification** with structured decision criteria.

### Calculation Logic

#### LLM-Determined Scoring
```python
classification = llm.invoke(prompt)
risk_score = classification.get('risk_score', 50)  # Default: 50
```

The LLM analyzes evidence and determines risk score based on:
1. **IP Whitelist Status**
2. **VirusTotal/AbuseIPDB Results**
3. **Number of Disabled Account Attempts**
4. **Historical Context**

### Decision Criteria (Provided to LLM)

```
DECISION CRITERIA:
- If IP is in internal/expected whitelist → FalsePositive (Risk: 10-20)
- If IP is NOT in whitelist → TruePositive (Risk: 70-90)
```

### Factors Affecting Risk Score

| Factor | Classification | Typical Risk Score | Impact |
|--------|----------------|-------------------|--------|
| **IP in Internal Whitelist** | FalsePositive | 10-20 | Low risk - authorized activity |
| **IP NOT in Whitelist** | TruePositive | 70-90 | High risk - unauthorized attempt |
| **Multiple Attempts** | TruePositive | 80-95 | Critical - persistent attack |
| **Known Malicious IP** | TruePositive | 85-95 | Critical - confirmed threat |
| **Insufficient Data** | Undetermined | 40-60 | Medium - needs review |

### LLM Prompt Structure

```python
prompt = f"""
Based on the investigation of disabled account sign-in attempts, provide your final classification.

EVIDENCE SUMMARY:
- IOCs: {iocs}
- Disabled account attempts: {attempts}
- Tool results: {tool_results}

DECISION CRITERIA:
- If IP is in internal/expected whitelist → FalsePositive
- If IP is NOT in whitelist → TruePositive

Provide response in JSON:
{{
    "classification": "TruePositive|FalsePositive|...",
    "risk_score": 0-100,
    "rationale": "...",
    "key_factors": [...]
}}
"""
```

### Error Handling
```python
try:
    # LLM classification
    risk_score = classification.get('risk_score', 50)
except Exception:
    # Fallback
    classification = 'Undetermined'
    risk_score = 50
```

### Classification Decision Tree

```
┌─────────────────────────────────────────┐
│   Disabled Account Sign-in Attempt      │
└──────────────┬──────────────────────────┘
               │
               ▼
    ┌──────────────────────┐
    │ Extract IOCs         │
    │ (Account, IP)        │
    └──────────┬───────────┘
               │
               ▼
    ┌──────────────────────────┐
    │ Query Disabled Account   │
    │ Attempt Logs             │
    └──────────┬───────────────┘
               │
               ▼
    ┌──────────────────────────┐
    │ Check IP Whitelist       │
    │ + VirusTotal/AbuseIPDB   │
    └──────────┬───────────────┘
               │
               ▼
    ┌──────────────────────────┐
    │ LLM Classification       │
    │ (Evidence Analysis)      │
    └──────┬───────────────────┘
           │
           ├─── IP IN WHITELIST ──────► FalsePositive (Risk: 10-20)
           │                             Authorized testing/admin
           │
           ├─── IP NOT IN WHITELIST ──► TruePositive (Risk: 70-90)
           │                             Unauthorized access attempt
           │
           ├─── MALICIOUS IP ─────────► TruePositive (Risk: 85-95)
           │                             Known attacker
           │
           └─── INSUFFICIENT DATA ────► Undetermined (Risk: 40-60)
                                         Manual review required
```

### Risk Score Ranges → Classification Mapping

| Score Range | Classification | Decision |
|-------------|----------------|----------|
| **85-95** | TruePositive | Known malicious IP attempting access |
| **70-84** | TruePositive | Unauthorized IP not in whitelist |
| **50-69** | Undetermined | Unclear evidence - review needed |
| **40-49** | Undetermined | Insufficient data |
| **10-39** | FalsePositive | Authorized testing or admin activity |

### LLM Scoring Considerations

The LLM evaluates:
1. **IP Reputation** - VirusTotal malicious count, AbuseIPDB confidence
2. **Whitelist Status** - Is IP in approved internal/expected list?
3. **Attempt Frequency** - Single vs. multiple attempts
4. **Historical Context** - Has this IP been seen before?
5. **Account Status** - Why was account disabled?

---

## Risk Score Comparison Matrix

### Classification → Risk Score Mapping (All Agents)

| Agent | TruePositive | FalsePositive | BenignPositive | Undetermined |
|-------|-------------|---------------|----------------|--------------|
| **Phishing** | 70-95 | 10-30 (LLM) | N/A | 40-60 (LLM) |
| **Login Identity** | 75-95 | 5-10 | 35 | 40-55 |
| **Exfiltration** | 70-90 | N/A | 20 | 40-50 |
| **Access Control** | 70-95 | 10-20 | N/A | 40-60 |

### Risk Factor Weight Comparison

| Risk Factor | Phishing | Login Identity | Exfiltration | Access Control |
|-------------|----------|----------------|--------------|----------------|
| **Malicious IP** | +10 per IP | +15 per IP (base 70) | +10 per IP | LLM (70-95) |
| **Network Transfer** | N/A | N/A | +5 per GB | N/A |
| **High-Risk Region** | N/A | Fixed 85 | N/A | N/A |
| **Impossible Travel** | N/A | Fixed 90 | N/A | N/A |
| **Brute Force** | N/A | Fixed 80 | N/A | N/A |
| **Whitelist Status** | N/A | -75 (to 10) | -50 (to 20) | -60 (to 10-20) |
| **Multiple Attempts** | N/A | Considered | N/A | LLM (+10-20) |

### Detection Threshold Comparison

| Metric | Phishing | Login Identity | Exfiltration | Access Control |
|--------|----------|----------------|--------------|----------------|
| **VirusTotal Malicious** | >= 2 | >= 2 | >= 2 | LLM evaluation |
| **VirusTotal Suspicious** | >= 5 | N/A | >= 3 | LLM evaluation |
| **AbuseIPDB High** | >= 75% | >= 75% | >= 75% | LLM evaluation |
| **AbuseIPDB Medium** | N/A | N/A | > 20% | N/A |
| **Failed Login Attempts** | N/A | > 5 (brute force) | N/A | N/A |

### Scoring Philosophy Differences

| Agent | Approach | Rationale |
|-------|----------|-----------|
| **Phishing** | Rule-based + LLM fallback | Clear malicious indicators; LLM for ambiguous cases |
| **Login Identity** | Pure rule-based | Well-defined behavioral patterns |
| **Exfiltration** | Rule-based with volume factor | Network data adds quantifiable risk |
| **Access Control** | LLM-dominant | Complex context requires nuanced analysis |

### Maximum Risk Scores

| Agent | Max Score | Reason |
|-------|-----------|--------|
| **Phishing** | 95 | Multiple malicious IOCs |
| **Login Identity** | 95 | Multiple malicious IPs |
| **Exfiltration** | 90 | Malicious IP + large transfer |
| **Access Control** | 95 | Known attacker + multiple attempts |

---

## Key Insights

### 1. **Malicious IP Detection is Universal**
All agents treat confirmed malicious IPs (VirusTotal >= 2 or AbuseIPDB >= 75%) as immediate TruePositive indicators with high risk scores (70-95).

### 2. **Scoring Granularity Varies**
- **Login Identity:** Most granular (10 different risk levels)
- **Exfiltration:** Dynamic based on volume
- **Phishing:** Additive per IOC
- **Access Control:** LLM-flexible

### 3. **Whitelist Effect is Significant**
Being on an approved whitelist reduces risk scores by **60-75 points** across all agents.

### 4. **Cap Mechanisms Prevent Over-Scoring**
All agents cap maximum scores (90-95) to prevent unrealistic risk inflation.

### 5. **Undetermined Default is Consistent**
When insufficient data exists, all agents default to **40-60 risk score** and require manual review.

---

## Implementation References

### Code Locations Summary

| Agent | Main Risk Scoring Function | File Path | Lines |
|-------|----------------------------|-----------|-------|
| **Phishing** | `classify_incident()` | `agents/phishing_agent/graph.py` | 540-695 |
| **Login Identity** | `classify_incident()` | `agents/login_identity_agent/graph.py` | 540-650 |
| **Login Identity (RDP)** | `detect_rdp_anomalies()` | `agents/login_identity_agent/tools/rdp_tools.py` | 495-565 |
| **Exfiltration** | `classify_incident()` | `agents/exfiltration_agent/graph.py` | 450-580 |
| **Access Control** | `llm_classify()` | `agents/access_control_agent/graph.py` | 260-335 |

---

**Document End** | For questions or updates, contact the SOC Development Team
