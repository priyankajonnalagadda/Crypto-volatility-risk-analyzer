import streamlit as st
import pandas as pd
import numpy as np
import yfinance as yf
import matplotlib.pyplot as plt

st.set_page_config(page_title="Crypto Risk Analyzer", layout="centered")

st.title("🔐 Crypto Volatility & Risk Analyzer")

coins = ["BTC-USD", "ETH-USD", "SOL-USD"]
selected_coin = st.selectbox("Select Cryptocurrency", coins)

data = yf.download(
    selected_coin,
    period="1y",
    interval="1d",
    progress=False
).reset_index()

data["Daily_Return"] = data["Close"].pct_change()
data["Volatility"] = data["Daily_Return"].rolling(7).std()
data.dropna(inplace=True)

v_min, v_max = data["Volatility"].min(), data["Volatility"].max()
data["Risk_Score"] = (data["Volatility"] - v_min) / (v_max - v_min) * 100

st.subheader("📊 Price Trend")
st.line_chart(data.set_index("Date")["Close"])

st.subheader("📉 Volatility")
st.line_chart(data.set_index("Date")["Volatility"])

st.subheader("🚦 Risk Score")
st.line_chart(data.set_index("Date")["Risk_Score"])

st.subheader("📋 Latest Risk Summary")
st.write(data[["Date", "Close", "Volatility", "Risk_Score"]].tail(5))
