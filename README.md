# 🛡️ Threat Intel Named Entity Recognition (NER) & IOC Extractor

An automated Natural Language Processing (NLP) pipeline designed to ingest unstructured cybersecurity threat intelligence reports from custom datasets and extract structured Indicators of Compromise (IOCs).

## 📌 Project Overview
Security Operations Centers (SOCs) receive raw threat intelligence feeds, whitepapers, and incident reports daily. Manually parsing prose to extract IP addresses, file hashes, threat actors, and vulnerability IDs into SIEM blocklists is time-consuming and inefficient. This project automates threat telemetry extraction using custom `spaCy` Entity Rulers, Regular Expressions (RegEx), and Pandas data analysis.

## 🛠️ Tech Stack
* **Language:** Python 3.10+
* **NLP Framework:** `spaCy` (Entity Ruler pipeline)
* **Data Processing & Analysis:** `pandas`, `json`, `matplotlib`, `seaborn`

## 📊 Dataset & Features
* **Source:** Custom Cyber Threat Intelligence Processed Dataset (`Cyber-Threat-Intelligence-Custom-Data_new_processed.csv`).
* **Attributes Extracted:**
  * **IPv4 Addresses:** Network indicators for C2 blocking.
  * **File Hashes (MD5 & SHA256):** Malware signatures for endpoint detection (EDR).
  * **Vulnerability IDs (CVEs):** Discovered software flaws requiring patches.
  * **Threat Actors & Malware Labels:** Annotated corpus categories.

## 📁 Repository Structure
```text
threat-intel-ioc-extractor/
│
├── data/
│   ├── Cyber-Threat-Intelligence-Custom-Data_new_processed.csv
├── src/
│   └── extractor.py    # Core IOC extraction engine pipeline
    └── analysis.py     # Exploratory Data Analysis notebook
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt