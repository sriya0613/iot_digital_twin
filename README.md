# Explainable Contextual Behavior Fingerprinting for IoT Device Threat Detection and Risk Assessment via Digital Twins

An end-to-end self-healing IoT security system that emulates IoT firmware as a digital twin, monitors multi-dimensional device behavior, detects threats using explainable hybrid ML, and autonomously contains and recovers compromised devices — all without modifying the original firmware.

## Key Results

| Metric | Value |
|--------|-------|
| Detection F1 | 0.863 |
| False Positive Rate | 2.0% |
| Containment Latency | 0.12s |
| Detection Latency (median) | 4.1s |
| Heal Success Rate | 89% (8/9) |
| Online Adaptation | 0% → 100% on unseen attacks |

## Architecture


<img width="1794" height="868" alt="image" src="https://github.com/user-attachments/assets/44128e4d-6015-4a6e-be5d-bd0e46e3c79a" />


### Module 1 — Digital Twin & Network Infrastructure
- **FirmAE/QEMU** emulation of D-Link DIR-868L router firmware
- **Open vSwitch** bridge with OpenFlow 1.3 for SDN-controlled networking
- **Ryu SDN Controller** for programmatic flow rule management
- **Linux network namespaces** for isolated attack/client simulation
- Mirror port for passive traffic monitoring

### Module 2 — Contextual Behavior Fingerprinting
- **45-feature behavioral fingerprint** extracted every 5 seconds
- 28 network features (Scapy) + 11 syscall features (/proc) + 6 energy features (psutil)
- Schema 2.0.0 contract enforcement with min-max normalization to [0,1]
- Ablation study: adding syscall + energy features halves FP rate (4% → 2%)

### Module 3 — Hybrid ML Detection & Explainability
- **XGBoost** binary classifier for known attack patterns
- **SGD Classifier** with `partial_fit()` for online learning
- **MLP Autoencoder** (benign-only) for novel/unknown threat detection
- **SHAP** explanations — top-5 feature impacts per alert
- Multi-class attack classification: scan, bruteforce, DoS, beacon
- Blended risk score: `0.5×confidence + 0.2×anomaly + 0.3×severity×confidence`

### Module 4 — Autonomous Response & Self-Healing
- **Tiered policy engine**: observe (<30) → rate-limit (30-70) → quarantine+heal (>70)
- **SDN containment** via Ryu REST API — MAC-based drop/meter rules in 0.12s
- **Graded verified rollback** — firmware restore with 3-window post-heal verification
- **Escalation mechanism** — 3 heals in 10 min triggers HOLD for human review
- **Streamlit dashboard** — real-time risk timeline, SHAP explanations, heal history

## Project Structure

```
├── network/              # Twin infrastructure (OVS, Ryu, watchdog, heal)
│   ├── twin_net.sh       # Master script: up/down/heal/status
│   ├── ryu_base.py       # Base Ryu SDN controller
│   └── watchdog.py       # Liveness monitoring
├── stream/               # Behavior fingerprinting (3 monitors)
│   ├── collectors.py     # Network, syscall, energy collectors
│   ├── pipeline.py       # Windowing, normalization, schema enforcement
│   └── run.py            # CLI: record, build, stream
├── persond/              # Policy, containment, healing, dashboard
│   ├── run_pipeline.py   # Full response chain
│   ├── policy.py         # Tiered risk-based policy engine
│   ├── containment.py    # Ryu REST SDN rule management
│   ├── healing_engine.py # Graded verified rollback
│   ├── threat_db.py      # SQLite threat database
│   └── dashboard.py      # Streamlit real-time dashboard
├── models_v3_hybrid/     # Trained hybrid model artifacts
├── contracts/            # JSON schemas for data contracts
├── data/                 # Training datasets and scalers
├── reports/              # Evaluation results and plots
├── tests/                # Unit and integration tests
├── run_live.sh           # All-in-one: monitors + detector + alerts
├── threat_model_v3.py    # HybridModel definition
├── train_detector_v3.py  # Training script
├── ablation.py           # Feature set ablation study
├── unknown_threat.py     # Novel threat detection evaluation
└── feedback_loop.py      # Online learning evaluation
```

## Running the System

All commands run from the project root on the twin host.

**Tab 1 — Start the digital twin:**
```bash
sudo bash network/twin_net.sh up
bash network/twin_net.sh status
```

**Tab 2 — Monitors + Detector:**
```bash
BRIDGED=1 MODEL_DIR=models_v3_hybrid bash run_live.sh --alerts-only
```

**Tab 3 — Policy + Containment + Healing:**
```bash
python3 persond/run_pipeline.py \
  --follow logs/alerts.jsonl \
  --containment ryu \
  --dpid 00005abf7a9e9d47 \
  --restore-cmd "sudo bash network/twin_net.sh heal"
```

**Tab 4 — Dashboard:**
```bash
streamlit run persond/dashboard.py      # binds 127.0.0.1 via .streamlit/config.toml
```

**Tab 5 — Launch an attack (from atk namespace):**
```bash
# Bruteforce
sudo ip netns exec atk bash -c 'for i in $(seq 1 100); do curl -s -o /dev/null -u admin:wrong http://192.168.0.1/HNAP1/; done'

# Port scan
sudo ip netns exec atk nmap -sS -p 1-1000 192.168.0.1

# DoS
sudo ip netns exec atk hping3 -S --flood -p 80 192.168.0.1

# Beacon (C2 simulation)
sudo ip netns exec atk bash -c 'while true; do curl -s -o /dev/null http://192.168.0.1; sleep 10; done'
```

## Technologies

- **Emulation**: FirmAE, QEMU (ARM), Open vSwitch, Ryu SDN Controller
- **Monitoring**: Scapy, Linux /proc, psutil
- **ML/AI**: XGBoost, scikit-learn (SGD), PyTorch (MLP autoencoder), SHAP
- **Infrastructure**: SQLite, Streamlit, tmux, Linux network namespaces
- **Target Device**: D-Link DIR-868L (firmware v2.05b02)

## Team

| Member | USN |
|--------|-----|
| SS Neranjana | PES2UG23CS606 |
| Tavishi Gupta | PES2UG23CS646 |
| Arshia Bora | PES2UG23CS094 |
| Sriya Ramachandrula | PES2UG23CS603 |

**Course**: UE23CS441A — Capstone Project  
**Guide**: Dr. Vinodha K  
**Project ID**: 20
