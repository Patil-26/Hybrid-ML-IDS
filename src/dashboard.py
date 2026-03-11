import streamlit as st
import pandas as pd
import os

st.title("Hybrid ML IDS Dashboard")

# get project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

log_path = os.path.join(BASE_DIR, "logs", "attack_logs.csv")

st.write("Looking for file at:", log_path)

if os.path.exists(log_path):

    data = pd.read_csv(log_path)

    st.success("Log file loaded")

    st.subheader("Recent Attacks")
    st.dataframe(data.tail(20))

    st.subheader("Blocked IPs")
    st.write(data["ip"].unique())

    st.subheader("Total Attacks Logged")
    st.write(len(data))

else:
    st.error("attack_logs.csv not found")