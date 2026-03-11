import streamlit as st
import pandas as pd
import os

LOG_FILE = "logs/attacks.log"
BLACKLIST_FILE = "logs/blacklist.txt"


st.set_page_config(page_title="IDS Dashboard", layout="wide")

st.title("Hybrid Machine Learning IDS Dashboard")

st.sidebar.header("System Status")
st.sidebar.success("IDS Running")

# -------- Attack Logs --------

st.header("Detected Intrusions")

if os.path.exists(LOG_FILE):

    data = pd.read_csv(
        LOG_FILE,
        names=["Timestamp", "Source IP", "Attack Type", "Confidence", "Action"]
    )

    st.dataframe(data)

    st.subheader("Total Attacks Detected")
    st.metric("Attacks", len(data))

else:
    st.info("No attacks logged yet.")


# -------- Blocked IPs --------

st.header("Blocked IP Addresses")

if os.path.exists(BLACKLIST_FILE):

    with open(BLACKLIST_FILE, "r") as f:
        ips = f.readlines()

    ips = [ip.strip() for ip in ips]

    st.write(ips)

    st.metric("Blocked IPs", len(ips))

else:
    st.info("No IPs blocked yet.")