# ThreatScan

AI-powered cybersecurity threat classifier. Paste a suspicious email, URL, server log entry, or code snippet and get an instant classification with NIST CSF mapping.

Built for **CY 201 — Intro to Cybersecurity** at Southeast Missouri State University.

## Features

- Classifies inputs as MALICIOUS / SUSPICIOUS / SAFE / INFORMATIONAL
- Confidence score with visual indicator
- Severity rating (Critical / High / Medium / Low / None)
- NIST CSF control mapping (ID.RA, DE.AE, RS.AN, etc.)
- Specific indicators explaining what triggered the classification
- Plain English explanation + remediation recommendation
- 4 input types: Email, URL, Log Entry, Code

## Project Structure

```
threatscan/
├── index.html        # Main HTML structure
├── css/
│   └── style.css     # All styles and CSS variables
├── js/
│   └── app.js        # Classification logic, API calls, DOM rendering
└── README.md
```

## Tech Stack

- Vanilla HTML / CSS / JavaScript — no frameworks
- LLM inference API for classification
- Fonts: Space Grotesk + Space Mono (Google Fonts)

## Running Locally

Just open `index.html` in a browser. No build step or server needed.

Note: requires a valid API key configured in `js/app.js` at the `API_URL` constant.

## Course Context

This project applies concepts from CY 201 to build a working threat detection tool:

- **Phishing patterns** — urgency language, spoofed domains, suspicious links
- **URL analysis** — typosquatting, suspicious TLDs, encoded payloads
- **Log analysis** — brute force detection, port scan signatures (also covered in Snort IDS labs)
- **Vulnerable code** — buffer overflows, SQL injection, unsafe C stdlib functions (gets, strcpy) — connects to CS 380 content

## Author

Tarunima Amisha · [github.com/amisha53](https://github.com/amisha53) · SEMO CS 2026
