import streamlit as st
from data.data_loader import load_bitcoin
from volatility.volatility_calc import volatility_analysis
from risk.risk_score import add_risk_score

st.set_page_config(page_title="Crypto Risk Analyzer", layout="wide")

st.title("📊 Crypto Volatility & Risk Analyzer")

st.markdown("Analyzing Bitcoin market risk using real-time data.")

# Load data
df = load_bitcoin()

st.subheader("🔍 Raw Data Preview")
st.dataframe(df.tail())

# Volatility
df = volatility_analysis()
df = add_risk_score(df)

st.subheader("⚠️ Risk Summary")
st.dataframe(df[["Date", "Close", "Volatility", "Risk_Score", "Risk_Level"]].tail())

latest = df.iloc[-1]

st.metric("Bitcoin Price (USD)", round(latest["Close"], 2))
st.metric("Risk Level", str(latest["Risk_Level"].iloc[0] if hasattr(latest["Risk_Level"], "iloc") else latest["Risk_Level"]))

st.success("Live crypto risk analysis completed successfully.")
