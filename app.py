import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(page_title="Crypto Volatility & Risk Intelligence", layout="wide")

st.title("🔐 Crypto Volatility & Risk Intelligence Dashboard")
st.caption("Stable deployment using precomputed CSV outputs (no live Yahoo dependency)")

with st.sidebar:
    st.header("⚙️ Data Source")
    ts_file = st.file_uploader("Upload final_timeseries_crypto_risk.csv", type=["csv"])
    summary_file = st.file_uploader("Upload final_coin_summary.csv", type=["csv"])
    alerts_file = st.file_uploader("Upload final_alerts.csv", type=["csv"])
    ml_file = st.file_uploader("Upload final_ml_forecast.csv", type=["csv"])

    st.header("⚙️ Controls")
    default_coin = None

def safe_read_csv(uploaded, parse_dates=None):
    if uploaded is None:
        return None
    try:
        return pd.read_csv(uploaded, parse_dates=parse_dates)
    except Exception:
        return pd.read_csv(uploaded)

ts_df = safe_read_csv(ts_file, parse_dates=["Date"])
summary_df = safe_read_csv(summary_file)
alerts_df = safe_read_csv(alerts_file, parse_dates=["Date"])
ml_df = safe_read_csv(ml_file, parse_dates=["Date"])

if ts_df is None or summary_df is None or alerts_df is None or ml_df is None:
    st.info("Upload all 4 CSV files in the sidebar to load the dashboard.")
    st.stop()

required_ts_cols = {"Date", "Coin", "Close", "Daily_Return", "Volatility", "Risk_Score", "Risk_Category"}
missing_cols = list(required_ts_cols - set(ts_df.columns))
if missing_cols:
    st.error(f"Timeseries CSV missing columns: {missing_cols}")
    st.stop()

ts_df["Date"] = pd.to_datetime(ts_df["Date"], errors="coerce")
ts_df = ts_df.dropna(subset=["Date"]).sort_values(["Coin", "Date"]).reset_index(drop=True)

coins = sorted(ts_df["Coin"].dropna().unique().tolist())

with st.sidebar:
    coin = st.selectbox("Select Coin", coins, index=0)
    start = st.date_input("Filter Start Date", value=ts_df["Date"].min().date())
    end = st.date_input("Filter End Date", value=ts_df["Date"].max().date())

start_dt = pd.to_datetime(start)
end_dt = pd.to_datetime(end)

coin_df = ts_df[(ts_df["Coin"] == coin) & (ts_df["Date"] >= start_dt) & (ts_df["Date"] <= end_dt)].copy()

if coin_df.empty:
    st.warning("No data in this date range. Change filters.")
    st.stop()

latest = coin_df.tail(1).iloc[0]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Price", f"{latest['Close']:.2f}", f"{latest['Daily_Return']*100:+.2f}%" if pd.notna(latest["Daily_Return"]) else None)
c2.metric("Volatility", f"{latest['Volatility']:.4f}" if pd.notna(latest["Volatility"]) else "N/A")
c3.metric("Risk Score", f"{latest['Risk_Score']:.0f}/100" if pd.notna(latest["Risk_Score"]) else "N/A")
c4.metric("Risk Category", str(latest["Risk_Category"]))

tab1, tab2, tab3, tab4 = st.tabs(["📈 Trends", "🚨 Alerts", "📊 Compare", "🤖 ML Forecast"])

with tab1:
    colA, colB = st.columns(2)
    with colA:
        st.subheader("Price Trend")
        st.line_chart(coin_df.set_index("Date")[["Close"]])
    with colB:
        st.subheader("Volatility Trend")
        st.line_chart(coin_df.set_index("Date")[["Volatility"]])

    st.subheader("Risk Score Trend")
    st.line_chart(coin_df.set_index("Date")[["Risk_Score"]])

with tab2:
    st.subheader("Recent Alerts")
    a = alerts_df.copy()
    if "Date" in a.columns:
        a["Date"] = pd.to_datetime(a["Date"], errors="coerce")
    a = a.dropna(subset=["Date"])
    a = a[(a["Coin"] == coin) & (a["Date"] >= start_dt) & (a["Date"] <= end_dt)].copy()
    a = a.sort_values("Date", ascending=False).head(25)

    if a.empty:
        st.success("No alerts in this range.")
    else:
        st.dataframe(a.reset_index(drop=True), use_container_width=True)

with tab3:
    st.subheader("Coin Summary (Precomputed)")
    st.dataframe(summary_df.reset_index(drop=True), use_container_width=True)

    if "Avg_Risk_Score" in summary_df.columns:
        safest = summary_df.sort_values("Avg_Risk_Score", ascending=True).head(3)
        riskiest = summary_df.sort_values("Avg_Risk_Score", ascending=False).head(3)

        c1, c2 = st.columns(2)
        with c1:
            st.subheader("✅ Top 3 Safest")
            st.dataframe(safest.reset_index(drop=True), use_container_width=True)
        with c2:
            st.subheader("⚠️ Top 3 Riskiest")
            st.dataframe(riskiest.reset_index(drop=True), use_container_width=True)

with tab4:
    st.subheader("ML Forecast (Precomputed)")
    m = ml_df.copy()
    if "Date" in m.columns:
        m["Date"] = pd.to_datetime(m["Date"], errors="coerce")
    if "Coin" not in m.columns:
        st.warning("ML forecast file does not have Coin column.")
    else:
        m = m[m["Coin"] == coin].copy()
        if m.empty:
            st.warning("No ML forecast available for this coin.")
        else:
            st.dataframe(m.reset_index(drop=True), use_container_width=True)

st.divider()
st.subheader("⬇️ Download")
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.download_button("Download Timeseries CSV", ts_df.to_csv(index=False), file_name="final_timeseries_crypto_risk.csv", mime="text/csv")
with col2:
    st.download_button("Download Summary CSV", summary_df.to_csv(index=False), file_name="final_coin_summary.csv", mime="text/csv")
with col3:
    st.download_button("Download Alerts CSV", alerts_df.to_csv(index=False), file_name="final_alerts.csv", mime="text/csv")
with col4:
    st.download_button("Download ML Forecast CSV", ml_df.to_csv(index=False), file_name="final_ml_forecast.csv", mime="text/csv")

