import streamlit as st
import pandas as pd
import numpy as np
import yfinance as yf
import matplotlib.pyplot as plt

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Crypto Volatility & Risk Analyzer",
    layout="centered"
)

st.title("🔐 Crypto Volatility & Risk Analyzer")
st.write("Live cloud-based analysis of cryptocurrency risk using volatility")

# ---------------- USER INPUT ----------------
coins = {
    "Bitcoin": "BTC-USD",
    "Ethereum": "ETH-USD",
    "Solana": "SOL-USD"
}

coin_name = st.selectbox("Select Cryptocurrency", list(coins.keys()))
coin = coins[coin_name]

# ---------------- DATA FETCH ----------------
data = yf.download(
    coin,
    period="1y",
    interval="1d",
    progress=False
)

data = data.reset_index()

# ---------------- FEATURE ENGINEERING ----------------
data["Daily_Return"] = data["Close"].pct_change()
data["Volatility"] = data["Daily_Return"].rolling(window=7).std()

data = data.dropna().reset_index(drop=True)

# ---------------- RISK SCORE ----------------
v_min = data["Volatility"].min()
v_max = data["Volatility"].max()

data["Risk_Score"] = (data["Volatility"] - v_min) / (v_max - v_min) * 100

def risk_category(score):
    if score < 33:
        return "Low Risk"
    elif score < 66:
        return "Medium Risk"
    else:
        return "High Risk"

data["Risk_Category"] = data["Risk_Score"].apply(risk_category)

# ---------------- VISUALS ----------------
st.subheader("📈 Price Trend")
st.line_chart(data.set_index("Date")["Close"])

st.subheader("📉 Volatility Trend (7-Day Rolling)")
st.line_chart(data.set_index("Date")["Volatility"])

st.subheader("🚦 Risk Score Trend")
st.line_chart(data.set_index("Date")["Risk_Score"])

# ---------------- PIE CHART ----------------
st.subheader("🧠 Risk Distribution")

risk_counts = data["Risk_Category"].value_counts()

fig1, ax1 = plt.subplots()
ax1.pie(
    risk_counts.values,
    labels=risk_counts.index,
    autopct="%1.1f%%",
    startangle=90
)
ax1.axis("equal")

st.pyplot(fig1)

# ---------------- SUMMARY TABLE ----------------
st.subheader("📋 Latest Risk Summary")

summary = data[[
    "Date",
    "Close",
    "Volatility",
    "Risk_Score",
    "Risk_Category"
]].tail(10)

st.dataframe(summary, use_container_width=True)

# ---------------- FINAL MESSAGE ----------------
st.success("✅ This is a live cloud-based crypto risk analysis dashboard")



