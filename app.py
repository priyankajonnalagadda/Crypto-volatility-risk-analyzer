import streamlit as st
import pandas as pd
import numpy as np
import yfinance as yf

# -----------------------------
# Page Config
# -----------------------------
st.set_page_config(
    page_title="Crypto Volatility & Risk Analyzer",
    layout="wide"
)

st.title("📊 Crypto Volatility & Risk Analyzer")
st.write("Analyze market volatility and investment risk of cryptocurrencies")

# -----------------------------
# Data Functions
# -----------------------------

@st.cache_data
def load_crypto_data(symbol, start="2022-01-01"):
    df = yf.download(symbol, start=start)
    df = df[['Close']]
    df.dropna(inplace=True)
    df['Return'] = df['Close'].pct_change()
    df.dropna(inplace=True)
    return df

def add_trends(df):
    df['MA_7'] = df['Close'].rolling(window=7).mean()
    df['MA_30'] = df['Close'].rolling(window=30).mean()
    df['Trend'] = np.where(df['MA_7'] > df['MA_30'], "Uptrend", "Downtrend")
    return df

def calculate_volatility(df):
    df['Rolling_Volatility'] = df['Return'].rolling(window=30).std() * np.sqrt(365)
    return df

def risk_score(vol):
    score = min(100, int(vol * 100))
    if score < 30:
        level = "Low Risk"
    elif score < 60:
        level = "Medium Risk"
    else:
        level = "High Risk"
    return score, level

# -----------------------------
# Sidebar / Selection
# -----------------------------

crypto_map = {
    "Bitcoin (BTC)": "BTC-USD",
    "Ethereum (ETH)": "ETH-USD",
    "Binance Coin (BNB)": "BNB-USD"
}

selected_crypto = st.selectbox(
    "Select Cryptocurrency",
    list(crypto_map.keys())
)

symbol = crypto_map[selected_crypto]

# -----------------------------
# Data Pipeline (CORRECT ORDER)
# -----------------------------

df = load_crypto_data(symbol)
df = add_trends(df)              # ✅ MUST come before plotting MA
df = calculate_volatility(df)

# -----------------------------
# Metrics
# -----------------------------

latest_vol = df['Rolling_Volatility'].iloc[-1]
score, risk_level = risk_score(latest_vol)

col1, col2, col3 = st.columns(3)
col1.metric("Volatility", f"{latest_vol:.2f}")
col2.metric("Risk Score", score)
col3.metric("Risk Category", risk_level)

# -----------------------------
# Charts
# -----------------------------

st.subheader("📈 Price Trend")
st.line_chart(df[['Close', 'MA_7', 'MA_30']])

st.subheader("📉 Rolling Volatility (30 Days)")
st.line_chart(df['Rolling_Volatility'])

# -----------------------------
# Summary Table
# -----------------------------

summary_df = pd.DataFrame({
    "Metric": ["Latest Volatility", "Risk Score", "Risk Category"],
    "Value": [round(latest_vol, 2), score, risk_level]
})

st.subheader("📋 Risk Summary")
st.table(summary_df)


