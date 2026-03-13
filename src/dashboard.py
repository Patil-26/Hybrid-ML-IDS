import streamlit as st
import pandas as pd
import json
import os
import time

# ─── Page Config ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="Hybrid ML-IDS Dashboard",
    layout="wide",
    page_icon="🛡️"
)

# ─── Paths ────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "logs", "attack_logs.csv")
EVAL_PATH = os.path.join(BASE_DIR, "logs", "evaluation_results.json")

# ─── Header ───────────────────────────────────────────────────────────
st.title("🛡️ Hybrid ML Intrusion Detection System")
st.markdown("This dashboard monitors your network in real time and shows all detected threats, blocked attackers, and how well the system is performing.")
st.caption("🔄 Dashboard auto-refreshes every 5 seconds")
st.divider()

# ═══════════════════════════════════════════════════════════════════════
# SECTION 1 — LIVE ATTACK MONITORING
# ═══════════════════════════════════════════════════════════════════════
st.header("🔴 Live Network Monitoring")

if os.path.exists(LOG_PATH):

    data = pd.read_csv(LOG_PATH)

    # Only keep valid columns
    expected_cols = ["timestamp", "ip", "attack_type", "confidence", "action"]
    data = data[[c for c in expected_cols if c in data.columns]]
    data = data.dropna(subset=["ip", "attack_type"])
    data["timestamp"] = pd.to_datetime(data["timestamp"])
    data["confidence"] = pd.to_numeric(data["confidence"], errors="coerce")

    if not data.empty:

        # ── Summary Cards ──
        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "🚨 Total Attacks Detected",
            len(data),
            help="Total number of malicious packets detected since monitoring started"
        )
        col2.metric(
            "👤 Unique Attackers",
            data["ip"].nunique(),
            help="Number of different IP addresses that have attacked"
        )
        col3.metric(
            "⚠️ Attack Types Found",
            data["attack_type"].nunique(),
            help="How many different types of attacks were detected"
        )
        col4.metric(
            "🎯 Avg Confidence",
            f"{data['confidence'].mean():.0%}",
            help="How confident the ML model is in its detections on average"
        )

        st.divider()

        # ── Recent Attacks Table ──
        st.subheader("📋 Recent Attacks")
        st.markdown("Showing the last 20 detected attacks on your network:")

        display_data = data.tail(20).copy()
        display_data = display_data.rename(columns={
            "timestamp": "🕐 Time",
            "ip": "🌐 Attacker IP",
            "attack_type": "⚠️ Attack Type",
            "confidence": "🎯 Confidence",
            "action": "🔒 Action Taken"
        })

        # Format confidence as percentage
        display_data["🎯 Confidence"] = display_data["🎯 Confidence"].apply(
            lambda x: f"{x:.0%}" if pd.notnull(x) else "N/A"
        )

        # Format action taken
        display_data["🔒 Action Taken"] = display_data["🔒 Action Taken"].apply(
            lambda x: "✅ Blocked" if x == "blocked" else "⚠️ Already Blocked"
        )

        st.dataframe(display_data, use_container_width=True, hide_index=True)

        st.divider()

        # ── Attack Trend ──
        st.subheader("📈 Attack Frequency Over Time")
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
            st.subheader("🌐 Top Attacking IPs")
            st.markdown("Which IP addresses attacked the most:")
            top_ips = data["ip"].value_counts().head(10)
            st.bar_chart(top_ips)

        with col2:
            st.subheader("⚠️ Types of Attacks")
            st.markdown("Breakdown of what kind of attacks were detected:")
            attack_types = data["attack_type"].value_counts()
            st.bar_chart(attack_types)

        st.divider()

        # ── Blocked IPs ──
        st.subheader("🚫 Blocked Attackers")
        st.markdown("These IP addresses have been automatically blocked by the system:")

        blocked = data[data["action"].str.contains("blocked", na=False)]["ip"].unique()
        if len(blocked) > 0:
            blocked_df = pd.DataFrame(blocked, columns=["Blocked IP Address"])
            st.dataframe(blocked_df, use_container_width=True, hide_index=True)
        else:
            st.info("No IPs blocked yet.")

    else:
        st.info("ℹ️ System is running but no attacks detected yet. This is good!")

else:
    st.info("ℹ️ Monitoring not started yet. Run monitor.py to begin.")

st.divider()

# ═══════════════════════════════════════════════════════════════════════
# SECTION 2 — HOW WELL IS THE SYSTEM PERFORMING?
# ═══════════════════════════════════════════════════════════════════════
st.header("📊 How Well Is The System Performing?")
st.markdown("These metrics show how accurately the system detects attacks vs normal traffic.")

if os.path.exists(EVAL_PATH):

    with open(EVAL_PATH, "r") as f:
        eval_results = json.load(f)

    # ── Simple explanation of metrics ──
    with st.expander("ℹ️ What do these numbers mean? (Click to expand)"):
        st.markdown("""
        - **Accuracy** — Out of all network packets, what % did the system classify correctly
        - **Precision** — Out of all packets flagged as attacks, what % were actually attacks (low = too many false alarms)
        - **Recall** — Out of all real attacks, what % did the system catch (low = attacks are being missed)
        - **F1 Score** — Overall performance score combining Precision and Recall (higher is better)
        """)

    st.divider()

    # ── Model Comparison Table ──
    st.subheader("🤖 Model Comparison")
    st.markdown("We trained 3 different AI models and combined them into one powerful Hybrid Ensemble:")

    table_data = []
    for r in eval_results:
        row = {
            "Model": r["model"],
            "Accuracy": f"{r['accuracy']*100:.2f}%",
            "Precision": f"{r['precision']*100:.2f}%",
            "Recall": f"{r['recall']*100:.2f}%",
            "F1 Score": f"{r['f1_score']*100:.2f}%",
        }
        if "cv_accuracy" in r:
            row["Cross Validation"] = f"{r['cv_accuracy']*100:.2f}% ± {r['cv_std']*100:.2f}%"
        else:
            row["Cross Validation"] = "—"
        table_data.append(row)

    st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)

    st.divider()

    # ── Confusion Matrix ──
    st.subheader("🎯 Attack Detection Breakdown — Hybrid Ensemble")
    st.markdown("This shows exactly how the system performed on test data:")

    ensemble = next((r for r in eval_results if r["model"] == "Weighted Ensemble"), None)

    if ensemble:

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "✅ Attacks Correctly Caught",
            f"{ensemble['tp']:,}",
            help="True Positives — real attacks that were detected"
        )
        col2.metric(
            "✅ Normal Traffic Correctly Passed",
            f"{ensemble['tn']:,}",
            help="True Negatives — normal packets correctly identified as safe"
        )
        col3.metric(
            "⚠️ False Alarms",
            f"{ensemble['fp']:,}",
            help="False Positives — normal traffic wrongly flagged as attack"
        )
        col4.metric(
            "🚨 Attacks Missed",
            f"{ensemble['fn']:,}",
            help="False Negatives — real attacks that slipped through (most dangerous)"
        )

        st.divider()

        if "cv_accuracy" in ensemble:
            st.subheader("🔁 Cross Validation Result")
            st.markdown("We tested the Hybrid Ensemble 5 times on different portions of data to make sure it's consistently accurate:")

            col1, col2 = st.columns(2)
            col1.metric("Average Accuracy Across 5 Tests", f"{ensemble['cv_accuracy']*100:.2f}%")
            col2.metric("Variation Between Tests", f"± {ensemble['cv_std']*100:.2f}%",
                       help="Lower variation means the model is more consistent")

else:
    st.warning("⚠️ Run evaluation.py first to see performance metrics.")

# ─── Auto Refresh ─────────────────────────────────────────────────────
time.sleep(5)
st.rerun()