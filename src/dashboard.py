import streamlit as st
import pandas as pd
import os
import time

st.set_page_config(page_title="Hybrid ML IDS Dashboard", layout="wide")

st.title("Hybrid ML Intrusion Detection System")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_path = os.path.join(BASE_DIR, "logs", "attack_logs.csv")

# Auto refresh every 5 seconds
st.caption("Dashboard auto-refreshes every 5 seconds")

if os.path.exists(log_path):

    data = pd.read_csv(log_path)

    if not data.empty:

        data["timestamp"] = pd.to_datetime(data["timestamp"])

        col1, col2, col3 = st.columns(3)

        col1.metric("Total Attacks", len(data))
        col2.metric("Unique Attackers", data["ip"].nunique())
        col3.metric("Attack Types", data["attack_type"].nunique())

        st.divider()

        st.subheader("Recent Attacks")
        st.dataframe(data.tail(20))

        st.divider()

        # Attack trend
        st.subheader("Attack Trend")

        attacks_per_min = (
            data.groupby(pd.Grouper(key="timestamp", freq="1Min"))
            .size()
            .reset_index(name="attacks")
        )

        st.line_chart(attacks_per_min.set_index("timestamp"))

        st.divider()

        # Top attacking IPs
        st.subheader("Top Attacking IPs")

        top_ips = data["ip"].value_counts().head(10)
        st.bar_chart(top_ips)

        st.divider()

        # Attack distribution
        st.subheader("Attack Distribution")

        attack_types = data["attack_type"].value_counts()
        st.bar_chart(attack_types)

    else:
        st.warning("Log file exists but contains no attacks.")

else:
    st.error("attack_logs.csv not found")

time.sleep(5)
st.rerun()