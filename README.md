# Hybrid ML Intrusion Detection System

A real-time network intrusion detection system that combines three machine learning models into a weighted ensemble to classify network traffic as normal or malicious. Built with Python, Scapy, Scikit-learn, and Streamlit.

---

## Overview

Traditional intrusion detection systems rely on static rule-based signatures that fail to detect novel attacks. This project takes a hybrid approach — combining rule-based detection with a weighted ensemble of three ML models trained on the NSL-KDD dataset to achieve 99.75% accuracy on unseen test data.

The system captures live network packets, extracts traffic features, classifies them in real time, logs detected attacks, blocks malicious IPs, and visualizes everything on a live dashboard.

---

## Demo

> Dashboard screenshot coming soon

---

## Architecture

```
Network Traffic
      ↓
Packet Capture (Scapy)
      ↓
Traffic Analysis + Feature Extraction
      ↓
Data Preprocessing (41-Column Feature Vector)
      ↓
┌─────────────────────────────────────────┐
│  Random Forest    SVM    Logistic Reg   │
│  Weight: 0.6   Weight: 0.2  Weight: 0.2│
└─────────────────────────────────────────┘
      ↓
Weighted Soft Voting Ensemble
      ↓
Attack Detected?
      ↓
Log Attack + Block IP + Update Dashboard
```

---

## Results

| Model | Accuracy | Precision | Recall | F1 Score |
|---|---|---|---|---|
| Random Forest | 99.87% | 99.94% | 99.77% | 99.86% |
| SVM | 95.40% | 96.12% | 93.94% | 95.02% |
| Logistic Regression | 95.28% | 95.90% | 93.91% | 94.89% |
| **Weighted Ensemble** | **99.75%** | **99.88%** | **99.59%** | **99.74%** |

**Cross Validation (5-Fold):** 99.68% ± 0.08%

The ensemble outperforms all individual models — proving the hybrid approach works.

---

## Features

- **Real-time packet capture** using Scapy
- **Hybrid detection** — ML prediction combined with rule-based DoS threshold
- **Weighted soft voting ensemble** — RF (0.6) + SVM (0.2) + LR (0.2)
- **Automated IP blocking** with persistent blacklist
- **Attack logging** with timestamp, IP, attack type, confidence score
- **Live Streamlit dashboard** with auto-refresh every 5 seconds
- **Full model evaluation** — accuracy, precision, recall, F1, confusion matrix, cross validation

---

## Tech Stack

| Category | Technology |
|---|---|
| Language | Python 3.13 |
| Packet Capture | Scapy |
| Machine Learning | Scikit-learn |
| Data Processing | Pandas, NumPy |
| Dashboard | Streamlit |
| Model Persistence | Joblib |

---

## Dataset

**NSL-KDD** — the standard benchmark dataset for IDS research.

- 125,973 training records
- 41 network traffic features
- Binary classification: normal vs attack
- Improved version of KDD99 with duplicate records removed

Attack types included: DoS, Probe, R2L, U2R

---

## Project Structure

```
Hybrid-ML-IDS/
│
├── src/
│   ├── monitor.py           # Real-time packet capture and detection
│   ├── traffic_analyzer.py  # Traffic analysis and DoS detection
│   ├── feature_engineer.py  # Feature extraction from packets
│   ├── preprocessing.py     # Feature alignment and dataset loading
│   ├── evaluation.py        # Model training and evaluation
│   ├── logger.py            # Attack event logging
│   ├── prevention.py        # IP blocking
│   └── dashboard.py         # Streamlit dashboard
│
├── models/
│   └── best_model.pkl       # Trained weighted ensemble (generated)
│
├── logs/
│   ├── attack_logs.csv      # Detected attack records (generated)
│   ├── blacklist.txt        # Blocked IP addresses (generated)
│   └── evaluation_results.json  # Model metrics (generated)
│
├── dataset/
│   └── KDDTrain+.txt        # NSL-KDD training dataset (not tracked)
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/Hybrid-ML-IDS.git
cd Hybrid-ML-IDS
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Download the dataset

Download NSL-KDD from [https://www.unb.ca/cic/datasets/nsl.html](https://www.unb.ca/cic/datasets/nsl.html)

Place `KDDTrain+.txt` inside the `dataset/` folder.

### 4. Train and evaluate models

```bash
python3 src/evaluation.py
```

This trains all three models, evaluates them, saves the weighted ensemble to `models/best_model.pkl` and writes results to `logs/evaluation_results.json`.

### 5. Start real-time monitoring

```bash
sudo python3 src/monitor.py
```

Requires sudo for raw packet capture access.

### 6. Launch the dashboard

```bash
streamlit run src/dashboard.py
```

Opens at `http://localhost:8501` and auto-refreshes every 5 seconds.

---

## How It Works

### Training Phase
The NSL-KDD dataset is loaded and preprocessed into a 41-column feature vector. Three models are trained — Random Forest on the full dataset, SVM and Logistic Regression on a 20k sample for speed. A weighted soft voting ensemble combines all three and is saved as `best_model.pkl`.

### Detection Phase
Scapy captures every network packet in real time. For each packet, the source IP and packet size are extracted and passed to the traffic analyzer, which tracks packet frequency per IP over a 5-second sliding window. The resulting features are preprocessed into the same 41-column format used during training and fed to the ensemble. If the model predicts an attack, or if the packet count exceeds the DoS threshold, the event is logged and the IP is blocked.

### Dashboard
Streamlit reads `attack_logs.csv` and `evaluation_results.json` every 5 seconds and renders live charts, metrics, and tables showing system activity and model performance.

---

## Detection Capabilities

| Attack Type | Detection Method |
|---|---|
| DoS (Denial of Service) | Rule-based threshold + ML |
| Probe / Port Scan | ML model |
| R2L (Remote to Local) | ML model |
| U2R (User to Root) | ML model |
| Unknown Intrusion | ML model |

---

## License

MIT License — free to use, modify and distribute.

---

## Author

**Atharva Patil**
- GitHub: [@Patil-26](https://github.com/Patil-26)
- LinkedIn: [linkedin.com/in/atharva-patil-046a25338](https://www.linkedin.com/in/atharva-patil-046a25338/)

---

> Built as a portfolio project exploring the intersection of cybersecurity and machine learning.