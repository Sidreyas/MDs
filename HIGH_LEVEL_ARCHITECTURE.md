# SOC AI Agents - High-Level Architecture (HLA)

## Document Information
- **Project**: SOC AI Agents
- **Version**: 1.0
- **Last Updated**: December 12, 2025
- **Status**: Production

---

## 1. Executive Summary

The SOC AI Agents system is an intelligent, automated Security Operations Center (SOC) platform that leverages Large Language Models (LLMs) and agentic workflows to investigate, analyze, and respond to security incidents. The system integrates with Azure Sentinel SIEM to automatically triage and investigate security alerts across multiple threat categories.

### Key Capabilities
- **Automated Incident Investigation**: Autonomous analysis of security incidents with minimal human intervention
- **Multi-Agent Architecture**: Specialized agents for different incident types (Phishing, Data Exfiltration, Identity/Login, Access Control)
- **Threat Intelligence Integration**: Real-time IOC validation using VirusTotal and AbuseIPDB
- **Intelligent Classification**: LLM-powered decision-making with rule-based guardrails
- **Incident Closure Automation**: Automatic incident resolution in Azure Sentinel with detailed justifications

---

## 2. System Architecture Overview

### 2.1 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SOC AI AGENTS PLATFORM                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNAL SYSTEMS                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐         │
│  │  Azure Sentinel  │  │   VirusTotal     │  │    AbuseIPDB     │         │
│  │      (SIEM)      │  │  Threat Intel    │  │   IP Reputation  │         │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘         │
│           │                     │                       │                    │
└───────────┼─────────────────────┼───────────────────────┼───────────────────┘
            │                     │                       │
            │                     │                       │
┌───────────▼─────────────────────▼───────────────────────▼───────────────────┐
│                          INTEGRATION LAYER                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐   │
│  │  Sentinel Tools    │  │  VirusTotal Tools  │  │  AbuseIPDB Tools   │   │
│  │  - Fetch Incidents │  │  - IP Validation   │  │  - IP Confidence   │   │
│  │  - Enrich Entities │  │  - Domain Check    │  │  - Abuse Reports   │   │
│  │  - Close Incidents │  │  - File Hash Check │  │                    │   │
│  │  - Add Comments    │  └────────────────────┘  └────────────────────┘   │
│  │  - Query Logs      │                                                    │
│  └────────────────────┘                                                    │
│                                                                              │
└───────────┬──────────────────────────────────────────────────────────────────┘
            │
            │
┌───────────▼──────────────────────────────────────────────────────────────────┐
│                       AGENT ORCHESTRATION LAYER                               │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │              INCIDENT DISPATCHER (Multi-Agent Router)              │     │
│  │                                                                     │     │
│  │  • Keyword-based routing to specialized agents                     │     │
│  │  • Pre-enrichment for context preparation                          │     │
│  │  • Dashboard generation and summary reporting                      │     │
│  └──────────┬──────────────────────────────────────────────────────────┘   │
│             │                                                                │
│             │                                                                │
│  ┌──────────▼────────┬──────────────────┬──────────────────┬──────────────┐│
│  │                   │                  │                  │              ││
│  │  Phishing Agent   │  Exfiltration    │  Login/Identity  │   Access     ││
│  │                   │     Agent        │     Agent        │  Control     ││
│  │                   │                  │                  │   Agent      ││
│  └───────────────────┴──────────────────┴──────────────────┴──────────────┘│
│                                                                               │
└───────────┬───────────────────────────────────────────────────────────────────┘
            │
            │
┌───────────▼───────────────────────────────────────────────────────────────────┐
│                          AGENT EXECUTION LAYER                                 │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      LangGraph Workflow Engine                        │   │
│  │                                                                       │   │
│  │  Phase 1: IOC Extraction       Phase 2: Investigation                │   │
│  │  ├─ Entity Enrichment          ├─ Threat Intel Validation            │   │
│  │  ├─ IOC Parsing                ├─ Behavioral Analysis                │   │
│  │  └─ Context Building           └─ Contextual Queries                 │   │
│  │                                                                       │   │
│  │  Phase 3: Classification       Phase 4: Remediation                  │   │
│  │  ├─ Rule-Based Checks          ├─ Incident Closure                   │   │
│  │  ├─ LLM Analysis               ├─ Report Generation                  │   │
│  │  └─ Risk Scoring               └─ Comment Addition                   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                                │
└────────────┬───────────────────────────────────────────────────────────────────┘
             │
             │
┌────────────▼───────────────────────────────────────────────────────────────────┐
│                           AI/LLM INFERENCE LAYER                                │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐  │
│  │   OpenAI GPT-4      │  │   Groq (LLama 3)    │  │   Claude Sonnet     │  │
│  │   (via Azure)       │  │   Fast Inference    │  │   (Anthropic)       │  │
│  └─────────────────────┘  └─────────────────────┘  └─────────────────────┘  │
│                                                                                 │
│  Use Cases: IOC Analysis, Risk Assessment, Classification, Reasoning          │
│                                                                                 │
└────────────┬────────────────────────────────────────────────────────────────────┘
             │
             │
┌────────────▼────────────────────────────────────────────────────────────────────┐
│                           DATA PERSISTENCE LAYER                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐       │
│  │  Investigation     │  │  Classification    │  │  Incident Logs     │       │
│  │  Reports (JSON)    │  │  Decisions         │  │  (Timestamped)     │       │
│  └────────────────────┘  └────────────────────┘  └────────────────────┘       │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Architecture

### 3.1 Agent Architecture (Common Pattern)

Each specialized agent follows a consistent LangGraph-based workflow pattern:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AGENT WORKFLOW PATTERN                            │
└─────────────────────────────────────────────────────────────────────────┘

  START
    │
    ▼
┌─────────────────────┐
│  1. IOC Extraction  │  ← Extract Indicators of Compromise from incident
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  2. Mandatory       │  ← Validate all IOCs with threat intelligence
│     Validation      │    (VirusTotal, AbuseIPDB, DNS, etc.)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  3. Investigation   │  ← Query logs, analyze behavior, gather context
│     (LLM-Driven)    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  4. Classification  │  ← Rule-based + LLM classification
│  (Hybrid Approach)  │    • TruePositive / FalsePositive
└──────────┬──────────┘    • BenignPositive / Undetermined
           │
           ▼
┌─────────────────────┐
│  5. Report          │  ← Generate JSON investigation report
│     Generation      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  6. Incident        │  ← Close incident in Sentinel with classification
│     Closure         │
└──────────┬──────────┘
           │
           ▼
          END
```

### 3.2 Specialized Agent Architectures

#### 3.2.1 Phishing Agent

```
Incident Type: Suspicious Email / Malicious Link / Attachment

Workflow:
  1. Extract IOCs
     ├─ Email addresses (sender, recipients)
     ├─ Domains (from URLs, sender domain)
     ├─ IP addresses (originating IP, header IPs)
     ├─ File hashes (attachment SHA256)
     └─ URLs (links in email body)
  
  2. Threat Intelligence Validation
     ├─ VirusTotal: Check all IPs, domains, file hashes, URLs
     ├─ DNS/MX/SPF/DMARC: Validate email authenticity
     └─ Domain reputation checks
  
  3. Email-Specific Analysis
     ├─ Header analysis (spoofing detection)
     ├─ Attachment analysis (file type, size, entropy)
     ├─ Link analysis (redirection chains)
     └─ Sender reputation
  
  4. Classification Logic
     ├─ ANY malicious IOC → TruePositive (70-95 risk)
     ├─ All legitimate + SPF/DKIM pass → BenignPositive
     ├─ Suspicious but unconfirmed → Undetermined
     └─ LLM fallback for edge cases

Tools: query_email_data, check_spf_dmarc, check_domain_virustotal
```

#### 3.2.2 Exfiltration Agent

```
Incident Type: Data Exfiltration / Unusual Upload / Large Transfer

Workflow:
  1. Extract IOCs
     ├─ Destination IPs (external)
     ├─ Destination domains/hosts
     ├─ Source hosts (internal)
     ├─ Processes (sftp, scp, python, etc.)
     └─ User accounts
  
  2. Network Intelligence
     ├─ VirusTotal: Check all external IPs/domains
     ├─ AbuseIPDB: Abuse confidence scores
     ├─ Allow-list: Check against known safe destinations
     └─ Geolocation: Check for unusual destinations
  
  3. Behavioral Analysis
     ├─ Query network logs for transfer volume
     ├─ Analyze transfer protocols (FTP, SFTP, HTTP)
     ├─ Check for data staging activities
     └─ Identify unusual patterns (time, volume)
  
  4. Classification Logic
     ├─ ANY malicious IP → TruePositive (70-90 risk)
     ├─ Large transfer to high-risk IP → TruePositive
     ├─ Allow-listed destination → BenignPositive
     └─ Insufficient context → Undetermined

Tools: query_network_logs, check_allow_list, categorize_destination
```

#### 3.2.3 Login/Identity Agent

```
Incident Type: Unexpected Location Login / Credential Compromise

Workflow:
  1. Extract IOCs
     ├─ User accounts
     ├─ Source IPs (login origin)
     ├─ Locations (geographic)
     ├─ Devices/User-Agents
     └─ Application accessed
  
  2. Geolocation & Reputation
     ├─ IP geolocation lookup
     ├─ AbuseIPDB confidence score
     ├─ VirusTotal IP reputation
     └─ Allow-list checking (known office IPs, VPN endpoints)
  
  3. Behavioral Analysis
     ├─ Query Azure AD sign-in logs
     ├─ Check user's historical login patterns
     ├─ Identify impossible travel scenarios
     ├─ Detect concurrent sessions from different locations
     └─ MFA status verification
  
  4. Classification Logic
     ├─ Malicious IP OR impossible travel → TruePositive
     ├─ Allow-listed IP + normal pattern → BenignPositive
     ├─ New location but legitimate → Undetermined
     └─ LLM-based context analysis

Tools: geolocate_ip, query_signin_logs, check_allowlist
```

#### 3.2.4 Disabled Account Agent

```
Incident Type: Login Attempts to Disabled Accounts

Workflow:
  1. Extract IOCs
     ├─ Disabled account names
     ├─ Source IPs
     ├─ Failed login timestamps
     └─ Applications targeted
  
  2. Threat Intelligence
     ├─ IP reputation (VirusTotal, AbuseIPDB)
     ├─ Geolocation analysis
     └─ Known attacker infrastructure
  
  3. Pattern Analysis
     ├─ Query failed login logs
     ├─ Identify brute-force patterns
     ├─ Check for credential stuffing
     └─ Analyze attack timing/frequency
  
  4. Classification Logic
     ├─ Malicious IP → TruePositive
     ├─ Brute-force pattern detected → TruePositive
     ├─ Single attempt + clean IP → FalsePositive
     └─ Multiple attempts + unknown IP → Undetermined

Tools: query_signin_logs, geolocate_ip, check_whitelist
```

---

## 4. Technology Stack

### 4.1 Core Framework
- **LangChain**: LLM orchestration and prompt management
- **LangGraph**: State machine and workflow orchestration
- **Python 3.11+**: Primary programming language

### 4.2 LLM Providers
- **OpenAI GPT-4**: Primary reasoning and analysis (via Azure)
- **Groq (LLama 3)**: Fast inference for classification tasks
- **Anthropic Claude**: Backup/alternative reasoning engine

### 4.3 External Integrations
- **Azure Sentinel**: SIEM for incident management
- **Azure Log Analytics**: Query logs and telemetry
- **VirusTotal API v3**: IOC validation and threat intelligence
- **AbuseIPDB API v2**: IP reputation and abuse confidence
- **Azure Active Directory**: Identity and authentication logs

### 4.4 Data Storage
- **JSON**: Investigation reports and structured data
- **CSV**: Bulk testing results and metrics
- **Markdown**: Documentation and summaries

### 4.5 Development Tools
- **Git**: Version control
- **pipenv**: Dependency management
- **dotenv**: Environment variable management

---

## 5. Data Flow Architecture

### 5.1 Incident Investigation Flow

```
1. INCIDENT INGESTION
   ↓
   Azure Sentinel Alert Created
   ↓
   [Incident Dispatcher]
   ↓
   Keywords Matched → Route to Specialized Agent
   ↓

2. IOC EXTRACTION
   ↓
   Enrich Incident Entities (Azure Sentinel API)
   ↓
   Parse IOCs: IPs, Domains, Hashes, Emails, URLs, Processes
   ↓

3. THREAT INTELLIGENCE VALIDATION
   ↓
   VirusTotal Lookup (IPs, Domains, Hashes, URLs)
   ↓
   AbuseIPDB Lookup (IP Abuse Confidence)
   ↓
   DNS/WHOIS/Geolocation Lookup
   ↓

4. CONTEXTUAL INVESTIGATION (LLM-Driven)
   ↓
   Adaptive Tool Selection (LLM decides which queries to run)
   ↓
   Query Azure Log Analytics
   ↓
   Behavioral Analysis
   ↓

5. CLASSIFICATION (Hybrid: Rules + LLM)
   ↓
   Rule-Based Checks:
   • ANY malicious IOC → TruePositive
   • All allow-listed → BenignPositive
   ↓
   LLM Fallback (if no clear rule match)
   ↓

6. DECISION & CLOSURE
   ↓
   Generate JSON Investigation Report
   ↓
   Close Incident in Sentinel (with classification + comment)
   ↓
   Store Report Locally
```

### 5.2 Data Transformation Pipeline

```
Raw Sentinel Incident (JSON)
  ↓
Enriched Entities (IPs, Hosts, Accounts, Processes)
  ↓
IOCs (Extracted & Deduplicated)
  ↓
Threat Intelligence Results (VirusTotal, AbuseIPDB)
  ↓
Investigation State (LangGraph State Object)
  ↓
Classification Decision (TP/FP/BP/Undetermined + Risk Score)
  ↓
Sentinel Closure Payload (Classification + Comment)
  ↓
Investigation Report (JSON with metadata)
```

---

## 6. Classification Logic

### 6.1 Classification Types

| Classification | Description | Risk Score Range | Auto-Close |
|---------------|-------------|------------------|------------|
| **TruePositive (TP)** | Confirmed malicious activity requiring immediate action | 70-100 | Yes |
| **FalsePositive (FP)** | Benign activity incorrectly flagged as malicious | 10-30 | Yes |
| **BenignPositive (BP)** | Legitimate activity that triggered alert (known safe) | 15-25 | Yes |
| **Undetermined** | Insufficient data or unclear intent | 35-60 | No (Manual Review) |

### 6.2 Classification Decision Tree

```
Classification Logic:
├─ ANY IOC flagged as MALICIOUS by VirusTotal (malicious_count > 0)?
│  └─ YES → TruePositive (Risk: 70 + IOC_count * 5)
│
├─ ANY IP with AbuseIPDB confidence ≥ 75%?
│  └─ YES → TruePositive (Risk: 75 + confidence * 0.2)
│
├─ ALL IOCs in ALLOW-LIST / WHITELIST?
│  └─ YES → BenignPositive (Risk: 20)
│
├─ Suspicious patterns but NO malicious IOCs?
│  └─ YES → Undetermined (Risk: 40-60, requires manual review)
│
└─ No clear indicators?
   └─ LLM Fallback Analysis (Context-based decision)
```

### 6.3 Critical Rule (All Agents)

**"SINGLE MALICIOUS IOC = TRUEPOSITIVE"**

Per SOC policy, a **single confirmed malicious IP or domain** is **sufficient evidence** to classify any incident as **TruePositive**, regardless of other benign indicators. This rule overrides LLM analysis.

---

## 7. Security & Compliance

### 7.1 Authentication
- **Azure Service Principal**: OAuth2 client credentials flow
- **API Keys**: Stored in `.env` file (not committed to repo)
- **Token Management**: Bearer tokens with 3599s lifetime (auto-refresh)

### 7.2 Rate Limiting
- **VirusTotal**: 4 requests/minute (free tier), 15s enforced delay
- **AbuseIPDB**: Standard rate limits respected
- **Azure APIs**: Default Azure throttling policies

### 7.3 Data Privacy
- **PII Handling**: No sensitive data logged to console
- **Report Storage**: Local JSON files only (not transmitted)
- **Incident Data**: Fetched on-demand, not stored permanently

### 7.4 Error Handling
- **API Failures**: Graceful degradation (skip failed calls, continue workflow)
- **LLM Timeouts**: Retry logic with exponential backoff
- **State Recovery**: LangGraph checkpointing for workflow resumption

---

## 8. Scalability & Performance

### 8.1 Current Limitations
- **Sequential Processing**: Incidents processed one at a time
- **Rate Limits**: VirusTotal API throttling (15s per request)
- **Single Threaded**: No parallel agent execution

### 8.2 Scalability Strategies (Future)

#### Horizontal Scaling
```
┌────────────────┐
│  Load Balancer │
└───────┬────────┘
        │
    ┌───┴───┬───────┬───────┐
    │       │       │       │
┌───▼───┐ ┌─▼─────┐ ┌─▼─────┐ ┌─▼─────┐
│Agent  │ │Agent  │ │Agent  │ │Agent  │
│Pool 1 │ │Pool 2 │ │Pool 3 │ │Pool 4 │
└───────┘ └───────┘ └───────┘ └───────┘
```

#### Async Processing
- **Celery/Redis**: Task queue for incident processing
- **Async IO**: Parallel API calls to VirusTotal/AbuseIPDB
- **Thread Pools**: Concurrent log queries

#### Caching
- **IOC Cache**: Redis cache for previously validated IOCs (TTL: 24h)
- **Allow-list Cache**: In-memory cache for known safe IPs/domains
- **LLM Response Cache**: Cache similar incident analysis

### 8.3 Performance Metrics

| Metric | Current Performance | Target Performance |
|--------|---------------------|-------------------|
| **Avg. Investigation Time** | 30-60 seconds | 15-30 seconds |
| **IOC Validation Time** | 15s per IOC | 5s per IOC (parallel) |
| **Incidents/Hour** | 60-120 | 300-500 |
| **Classification Accuracy** | 85-92% | 95%+ |

---

## 9. Monitoring & Observability

### 9.1 Logging
- **Structured Logging**: Timestamped logs with incident IDs
- **Log Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Log Storage**: `phishing_agent.log`, `investigation.log`, etc.

### 9.2 Metrics (Proposed)
- **Incident Processing Rate**: Incidents processed per hour
- **Classification Distribution**: TP/FP/BP/Undetermined counts
- **Agent Performance**: Avg. time per agent type
- **API Latency**: Response times for VirusTotal, AbuseIPDB, Sentinel
- **Error Rate**: Failed investigations per 1000 incidents

### 9.3 Alerting (Future)
- **Failed Investigations**: Alert on repeated agent failures
- **API Quota Exhaustion**: Alert on rate limit approaching
- **High-Risk Incidents**: Immediate notification for TP with risk >90

---

## 10. Deployment Architecture

### 10.1 Current Deployment
```
Development Environment:
├─ Local Machine (Ubuntu/Windows)
├─ Python Virtual Environment (pipenv)
├─ .env file for API keys
└─ Manual execution (python main.py)
```

### 10.2 Recommended Production Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│                     PRODUCTION DEPLOYMENT                        │
└─────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│                      AZURE CLOUD PLATFORM                       │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐     │
│  │         Azure Kubernetes Service (AKS)               │     │
│  │                                                       │     │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │     │
│  │  │ Phishing    │  │ Exfiltration│  │ Login/ID    │ │     │
│  │  │ Agent Pod   │  │ Agent Pod   │  │ Agent Pod   │ │     │
│  │  └─────────────┘  └─────────────┘  └─────────────┘ │     │
│  │                                                       │     │
│  │  ┌─────────────┐  ┌─────────────┐                   │     │
│  │  │ Access Ctrl │  │ Dispatcher  │                   │     │
│  │  │ Agent Pod   │  │    Pod      │                   │     │
│  │  └─────────────┘  └─────────────┘                   │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐     │
│  │            Azure Container Registry (ACR)            │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐     │
│  │           Azure Key Vault (Secrets Storage)          │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐     │
│  │         Azure Storage (Reports & Logs)               │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐     │
│  │         Azure Monitor + Application Insights         │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Trigger: Azure Sentinel Automation Rule → Webhook → AKS Pod
```

---

## 11. Future Enhancements

### 11.1 Planned Features
1. **Multi-Agent Collaboration**
   - Cross-agent correlation (e.g., phishing → lateral movement detection)
   - Shared context store for related incidents

2. **Machine Learning Integration**
   - Custom ML models for classification (complement LLM)
   - Anomaly detection for behavioral baselines

3. **Feedback Loop**
   - SOC analyst feedback on classifications
   - Fine-tuning LLM prompts based on feedback

4. **Automated Remediation**
   - Block malicious IPs in firewall
   - Quarantine phishing emails
   - Disable compromised accounts

5. **Dashboard & Visualization**
   - Real-time incident processing dashboard
   - Classification accuracy metrics
   - Agent performance analytics

6. **Additional Agents**
   - Malware Agent (file-based threats)
   - DDoS Detection Agent
   - Insider Threat Agent
   - Ransomware Detection Agent

### 11.2 Technical Debt
- [ ] Refactor common code into shared libraries
- [ ] Implement comprehensive unit tests (coverage >80%)
- [ ] Add integration tests for end-to-end workflows
- [ ] Standardize error handling across all agents
- [ ] Optimize LLM token usage (reduce costs)

---

## 12. Appendix

### 12.1 Agent Routing Keywords

| Agent Type | Keywords |
|-----------|----------|
| **Phishing** | phishing, phish, email, malicious email, suspicious email, malicious link, malicious attachment, email threat |
| **Exfiltration** | exfiltration, data exfiltration, data transfer, unusual upload, large transfer, data leak, data breach |
| **Login/Identity** | login, sign-in, authentication, unexpected location, credential compromise, impossible travel, geographic anomaly |
| **Disabled Account** | disabled account, disabled user, deactivated account, terminated employee login |

### 12.2 File Structure
```
SOC_Agents/
├── agents/
│   ├── phishing_agent/
│   │   ├── graph.py              # LangGraph workflow
│   │   ├── main.py               # Entry point
│   │   ├── state.py              # State definitions
│   │   └── tools/                # Agent-specific tools
│   ├── exfiltration_agent/
│   ├── login_identity_agent/
│   └── disabled_account_agent/
├── common/
│   ├── tools/
│   │   ├── sentinel_tools.py     # Azure Sentinel integration
│   │   ├── virustotal_tools.py   # VirusTotal API
│   │   └── abuseipdb_tools.py    # AbuseIPDB API
│   ├── config.py                 # Shared configuration
│   └── utils.py                  # Utility functions
├── incident_dispatcher.py        # Multi-agent router
├── docs/                         # Documentation
├── .env                          # Environment variables (not committed)
└── requirements.txt              # Python dependencies
```

### 12.3 Environment Variables
```bash
# Azure Sentinel
TENANT_ID=<your-tenant-id>
CLIENT_ID=<your-client-id>
CLIENT_SECRET=<your-client-secret>
SUBSCRIPTION_ID=<your-subscription-id>
RESOURCE_GROUP=<your-resource-group>
WORKSPACE_NAME=<your-workspace-name>

# Threat Intelligence
VIRUSTOTAL_API_KEY=<your-vt-api-key>
ABUSEIPDB_API_KEY=<your-abuseipdb-key>

# LLM Providers
GROQ_API_KEY=<your-groq-api-key>
OPENAI_API_KEY=<your-openai-key>
```

### 12.4 Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **LangGraph over LangChain** | Better state management, workflow visualization, error recovery |
| **Rule-Based + LLM Classification** | Deterministic decisions for clear cases, LLM for ambiguity |
| **Groq for Fast Inference** | 10x faster than OpenAI for classification tasks |
| **JSON Reports** | Structured, queryable, machine-readable format |
| **Manual Review for Undetermined** | Safety net to prevent incorrect auto-closure |

---

## 13. Glossary

- **IOC**: Indicator of Compromise (IP, domain, hash, email, URL)
- **SIEM**: Security Information and Event Management
- **SOC**: Security Operations Center
- **TP/FP/BP**: TruePositive / FalsePositive / BenignPositive
- **LangGraph**: State machine framework for LLM workflows
- **LangChain**: Framework for building LLM applications
- **Azure Sentinel**: Microsoft's cloud-native SIEM solution

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Dec 12, 2025 | AI Assistant | Initial HLA document created |

---

**END OF DOCUMENT**
