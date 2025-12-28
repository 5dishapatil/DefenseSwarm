# 🛡️ Defense Swarm: AI-Powered Security SOC

### *Protecting Cloud Infrastructure with a Swarm of Specialized AI Agents*

## 🚨 The Problem
Modern Security Operations Centers (SOCs) are overwhelmed.
- **Too many alerts:** Analysts ignore 40% of alerts due to fatigue.
- **Static Rules fail:** Hackers change tactics faster than firewalls can update.
- **Insider Threats:** Legitimate credentials (like stolen Admin passwords) bypass traditional defenses.

## 💡 The Solution
**Defense Swarm** is an intelligent, multi-agent security layer that sits *on top* of Microsoft Sentinel. Instead of static rules, it uses **Generative AI** (Phi-3/GPT) + **Behavioral Mathematics** to detect threats dynamically.

## 🏗️ The Architecture (The "Swarm")



Our system uses **2 Specialized Agents** to analyze every threat:

### **🕵️ Agent 1: The Screener (Context-Aware LLM)**
- **Role:** The "Bouncer".
- **Tech:** Local LLM (Phi-3 / GPT-20B) + Regex.
- **Capabilities:**
    - Masks PII (Emails/Phone numbers) *before* processing.
    - Detects **Prompt Injection** (e.g., "Ignore all rules").
    - **Context-Aware:** Distinguishes between an *Admin* running `DROP DATABASE` (Allowed) and a *Guest* trying the same (Blocked).

### **🧠 Agent 2: The Investigator (Behavioral Math)**
- **Role:** The "Mathematician".
- **Tech:** Python Logic + Weighted Risk Algorithm.
- **Capabilities:**
    - Ignores language; looks at **Velocity** (Speed) and **Spread** (Resource Access).
    - Detects **Brute Force** and **Data Exfiltration** even if the attacker uses valid credentials.
    - **Formula:** `Risk = (0.5 * Velocity_Score) + (0.5 * Spread_Score)`

---

## 🚀 How to Run It

### Prerequisites
- Python 3.10+
- Azure Functions Core Tools
- Ollama (running `gpt-oss:20b` or `phi3`)

### Installation
1. Clone the repo:
   ```bash
   git clone [https://github.com/5dishapatil/DefenseSwarm.git](https://github.com/5dishapatil/DefenseSwarm.git)
