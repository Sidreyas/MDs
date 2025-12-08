# Disabled Account Agent

Autonomous SOC agent for investigating sign-in attempts to disabled accounts.

## Overview

This agent automatically investigates incidents related to sign-in attempts to disabled accounts. It determines whether the attempt is from an internal/expected IP (FalsePositive) or an external/unexpected IP (TruePositive).

## Decision Logic

According to SOC analyst requirements:
- **If IP is internal/expected** → FalsePositive (not malicious, internal system)
- **If IP is external/unexpected** → TruePositive (genuine security alert)

## Internal/Expected IP Whitelist

```
8.8.8.8, 1.1.1.1, 9.9.9.9
192.168.1.10, 172.16.0.5, 10.0.0.8
203.0.113.5, 198.51.100.7, 192.0.2.1
203.0.113.9, 198.51.100.11, 192.0.2.12
203.0.113.13, 198.51.100.14, 192.0.2.15
```

## Features

- ✅ Automatic IOC extraction (accounts, IPs)
- ✅ Query disabled account attempt logs from Azure Log Analytics
- ✅ IP whitelist validation
- ✅ Threat intelligence checks (VirusTotal, AbuseIPDB)
- ✅ Geolocation analysis
- ✅ Automatic incident closure for FalsePositives
- ✅ JSON report generation

## Usage

```bash
cd /path/to/SOC_Agents
python -m agents.disabled_account_agent.main
```

## Workflow

1. **Extract IOCs** - Get username and IP from incident
2. **Query Logs** - Fetch disabled account attempt history
3. **Validate IOCs** - Check IP against whitelist and threat intel
4. **Classify** - LLM determines TruePositive or FalsePositive
5. **Close/Escalate** - Auto-close FP or escalate TP

## Tools

- `check_ip_internal_whitelist` - Primary decision tool
- `query_disabled_account_logs` - Get attempt history
- `check_ip_virustotal` - Threat intelligence
- `check_ip_abuseipdb` - Abuse confidence
- `get_ip_geolocation` - Location analysis

## Reports

Investigation reports are saved to `reports/incident_<number>_report_<timestamp>.json`
