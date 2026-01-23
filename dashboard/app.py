# ===== FIX PYTHON PATH (VERY IMPORTANT FOR STREAMLIT CLOUD) =====
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ===== NOW IMPORT PROJECT MODULES =====
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

from data.data_loader import load_bitcoin
from volatility.volatility_calc import volatility_analysis
from risk.risk_score import add_risk_score

# ===== STREAMLIT PAGE CONFIG =====
st.set_page_config(
    page_title="Crypto Volatility & Risk Analyzer",
    layout="wide"
)

# ===== TITLE =====
st.title("🚀 Crypto Volatility & Risk Analyzer")
st.markdown(
    "This dashboard analyzes **Bitcoin market data**, measures **volatility**, "
    "and converts it into an easy-to-understand **risk score** for investors."
)

# ===== LOAD DATA =====
st.header("📥 Data Collection")
df = load_bitcoin()
st.write("Latest raw Bitcoin data:")
st.dataframe(df.tail())

# ===== VOLATILITY ANALYSIS =====
st.header("📉 Volatility Analysis")
df = volatility_analysis()

st.line_chart(
    df.set_index("Date")["Volatility"],
    use_container_width=True
)

# ===== RISK SCORING =====
st.header("⚠️ Risk Scoring")
df = add_risk_score(df)

st.dataframe(
    df[["Date", "Close", "Volatility", "Risk_Score", "Risk_Level"]].tail(10),
    use_container_width=True
)

# ===== LATEST DAY SUMMARY =====
latest = df.iloc[-1]

risk_level = (
    latest["Risk_Level"].iloc[0]
    if hasattr(latest["Risk_Level"], "iloc")
    else latest["Risk_Level"]
)

risk_score = (
    latest["Risk_Score"].iloc[0]
    if hasattr(latest["Risk_Score"], "iloc")
    else latest["Risk_Score"]
)

st.header("📊 Latest Market Summary")

col1, col2, col3 = st.columns(3)

col1.metric("💰 Bitcoin Price (USD)", round(latest["Close"], 2))
col2.metric("📉 Volatility", round(latest["Volatility"], 5))
col3.metric("🚦 Risk Score", risk_score)

# ===== RISK INTERPRETATION =====
st.subheader("🧠 Risk Interpretation")

if risk_level == "High Risk":
    st.error("⚠️ High market volatility detected. Suitable only for high-risk investors.")
elif risk_level == "Medium Risk":
    st.warning("ℹ️ Moderate risk. A balanced investment strategy is recommended.")
else:
    st.success("✅ Market is relatively stable. Suitable for conservative investors.")

# ===== RISK DISTRIBUTION =====
st.header("📊 Risk Distribution")

risk_counts = df["Risk_Level"].value_counts()

fig1, ax1 = plt.subplots()
risk_counts.plot(kind="bar", ax=ax1)
ax1.set_title("Risk Level Distribution")
ax1.set_xlabel("Risk Level")
ax1.set_ylabel("Number of Days")
st.pyplot(fig1)

fig2, ax2 = plt.subplots()
risk_counts.plot(kind="pie", autopct="%1.1f%%", startangle=90, ax=ax2)
ax2.set_ylabel("")
ax2.set_title("Risk Level Percentage Distribution")
st.pyplot(fig2)

# ===== FOOTER =====
st.markdown("---")
st.caption(
    "📌 Project: Crypto Volatility & Risk Analyzer | "
    "Data Source: Yahoo Finance | "
    "Deployment: Streamlit Cloud"
)

