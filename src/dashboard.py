import streamlit as st
import pandas as pd
import json
import os
import time

# ─── Page Config ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="Hybrid ML-IDS Dashboard",
    layout="wide",
    page_icon=None
)

# ─── Paths ────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "logs", "attack_logs.csv")
EVAL_PATH = os.path.join(BASE_DIR, "logs", "evaluation_results.json")

# ─── Header ───────────────────────────────────────────────────────────
st.title("Hybrid ML Intrusion Detection System")
st.markdown("This dashboard monitors your network in real time and shows all detected threats, blocked attackers, and how well the system is performing.")
st.caption("Dashboard auto-refreshes every 5 seconds")
st.divider()

# ═══════════════════════════════════════════════════════════════════════
# SECTION 1 — LIVE ATTACK MONITORING
# ═══════════════════════════════════════════════════════════════════════
st.header("Live Network Monitoring")

if os.path.exists(LOG_PATH):

    data = pd.read_csv(LOG_PATH)

    expected_cols = ["timestamp", "ip", "attack_type", "confidence", "action"]
    data = data[[c for c in expected_cols if c in data.columns]]
    data = data.dropna(subset=["ip", "attack_type"])
    data["timestamp"] = pd.to_datetime(data["timestamp"])
    data["confidence"] = pd.to_numeric(data["confidence"], errors="coerce")

    if not data.empty:

        # ── Summary Cards ──
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Attacks Detected", len(data))
        col2.metric("Unique Attackers",        data["ip"].nunique())
        col3.metric("Attack Types Found",      data["attack_type"].nunique())
        col4.metric("Avg Confidence",          f"{data['confidence'].mean():.0%}")

        st.divider()

        # ── Recent Attacks Table ──
        st.subheader("Recent Attacks")
        st.markdown("Showing the last 20 detected attacks on your network:")

        display_data = data.tail(20).copy().sort_values("timestamp", ascending=False)
        display_data["confidence"] = display_data["confidence"].apply(
            lambda x: f"{x:.0%}" if pd.notnull(x) else "—"
        )
        display_data["action"] = display_data["action"].apply(
            lambda x: "Blocked" if x == "blocked" else "Already Blocked"
        )
        display_data = display_data.rename(columns={
            "timestamp":   "Time",
            "ip":          "Attacker IP",
            "attack_type": "Attack Type",
            "confidence":  "Confidence",
            "action":      "Action Taken"
        })

        st.dataframe(display_data, width="stretch", hide_index=True, height=800)

        st.divider()

        # ── Attack Trend ──
        st.subheader("Attack Frequency Over Time")
        st.markdown("This graph shows when attacks happened and how many occurred per minute:")

        attacks_per_min = (
            data.groupby(pd.Grouper(key="timestamp", freq="1Min"))
            .size()
            .reset_index(name="Number of Attacks")
        )
        st.line_chart(attacks_per_min.set_index("timestamp"))

        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Top Attacking IPs")
            st.markdown("Which IP addresses attacked the most:")
            st.bar_chart(data["ip"].value_counts().head(10))

        with col2:
            st.subheader("Types of Attacks")
            st.markdown("Breakdown of what kind of attacks were detected:")
            st.bar_chart(data["attack_type"].value_counts())

        st.divider()

        # ── Blocked IPs ──
        st.subheader("Blocked Attackers")
        st.markdown("These IP addresses have been automatically blocked by the system:")

        blocked = data["ip"].unique()
        blocked_df = pd.DataFrame(blocked, columns=["Blocked IP Address"])
        st.dataframe(blocked_df, width="stretch", hide_index=True)

    else:
        st.info("System is running but no attacks detected yet.")

else:
    st.info("Monitoring not started yet. Run monitor.py to begin.")

st.divider()

# ═══════════════════════════════════════════════════════════════════════
# SECTION 2 — MODEL PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════
st.header("Model Performance")
st.markdown("These metrics show how accurately the system detects attacks vs normal traffic.")

if os.path.exists(EVAL_PATH):

    with open(EVAL_PATH, "r") as f:
        eval_results = json.load(f)

    with st.expander("What do these numbers mean? (Click to expand)"):
        st.markdown("""
- **Accuracy** — Out of all network packets, what % did the system classify correctly
- **Precision** — Out of all packets flagged as attacks, what % were actually attacks (low = too many false alarms)
- **Recall** — Out of all real attacks, what % did the system catch (low = attacks are being missed)
- **F1 Score** — Overall performance score combining Precision and Recall (higher is better)
- **Attacks Caught (TP)** — Real attacks that were correctly detected
- **Normal Passed (TN)** — Normal traffic correctly identified as safe
- **False Alarms (FP)** — Normal traffic wrongly flagged as an attack
- **Attacks Missed (FN)** — Real attacks that slipped through (most dangerous)
        """)

    st.divider()

    # ── Model Comparison Table ──
    st.subheader("Model Comparison")
    st.markdown("We trained 3 different AI models and combined them into one powerful Hybrid Ensemble:")

    rows = []
    for r in eval_results:
        row = {
            "Model":            r["model"],
            "Accuracy":         f"{r['accuracy']*100:.2f}%",
            "Precision":        f"{r['precision']*100:.2f}%",
            "Recall":           f"{r['recall']*100:.2f}%",
            "F1 Score":         f"{r['f1_score']*100:.2f}%",
            "Cross Validation": f"{r['cv_accuracy']*100:.2f}% (±{r['cv_std']*100:.2f}%)" if "cv_accuracy" in r else "—"
        }
        rows.append(row)

    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

    st.divider()

    # ── Individual Model Performance Table ──
    st.subheader("Individual Model Performance")
    st.markdown("Detailed breakdown of each model's performance on the test dataset:")

    individual_rows = []
    for r in eval_results:
        individual_rows.append({
            "Model":           r["model"],
            "Accuracy":        f"{r['accuracy']*100:.2f}%",
            "Precision":       f"{r['precision']*100:.2f}%",
            "Recall":          f"{r['recall']*100:.2f}%",
            "F1 Score":        f"{r['f1_score']*100:.2f}%",
            "Attacks Caught":  f"{r['tp']:,}",
            "Normal Passed":   f"{r['tn']:,}",
            "False Alarms":    f"{r['fp']:,}",
            "Attacks Missed":  f"{r['fn']:,}",
        })

    st.dataframe(pd.DataFrame(individual_rows), width="stretch", hide_index=True)

    st.divider()

    # ── Confusion Matrix ──
    st.subheader("Attack Detection Breakdown — Weighted Ensemble")
    st.markdown("How the final ensemble model performed on unseen test data:")

    ensemble = next((r for r in eval_results if r["model"] == "Weighted Ensemble"), None)

    if ensemble:

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Attacks Correctly Caught", f"{ensemble['tp']:,}")
        col2.metric("Normal Traffic Passed",     f"{ensemble['tn']:,}")
        col3.metric("False Alarms",              f"{ensemble['fp']:,}")
        col4.metric("Attacks Missed",            f"{ensemble['fn']:,}")

        st.divider()

        if "cv_accuracy" in ensemble:
            st.subheader("Cross Validation — Weighted Ensemble")
            st.markdown("Model tested 5 times on different data splits to verify consistency:")
            col1, col2 = st.columns(2)
            col1.metric("Average Accuracy", f"{ensemble['cv_accuracy']*100:.2f}%")
            col2.metric("Variation",        f"±{ensemble['cv_std']*100:.2f}%")

else:
    st.warning("Run evaluation.py first to see model performance metrics.")

# ─── Auto Refresh ─────────────────────────────────────────────────────
time.sleep(5)
st.rerun()