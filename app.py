import streamlit as st
import pandas as pd
import numpy as np
import yfinance as yf

st.set_page_config(page_title="Crypto Volatility & Risk Intelligence", layout="wide")

st.title("🔐 Crypto Volatility & Risk Intelligence Dashboard")
st.caption("Real-time crypto risk analysis using volatility, risk scores, alerts, portfolio risk, and ML forecasting")

coins_map = {
    "Bitcoin (BTC)": "BTC-USD",
    "Ethereum (ETH)": "ETH-USD",
    "BNB": "BNB-USD",
    "Solana (SOL)": "SOL-USD",
    "XRP": "XRP-USD"
}

tab_main, tab_compare, tab_portfolio, tab_ml, tab_data = st.tabs(
    ["📈 Single Coin", "📊 Compare Coins", "💼 Portfolio", "🤖 ML Forecast", "⬇️ Download/Data"]
)

@st.cache_data
def load_data(ticker, start_date):
    df = yf.download(ticker, start=start_date, progress=False, auto_adjust=False, group_by="column")
    if df is None or df.empty:
        return pd.DataFrame(columns=["Date", "Close"])
    df = df.reset_index()

    if isinstance(df.columns, pd.MultiIndex):
        df.columns = [c[0] for c in df.columns]

    if "Adj Close" in df.columns:
        df["Close"] = df["Adj Close"]

    if "Date" not in df.columns or "Close" not in df.columns:
        return pd.DataFrame(columns=["Date", "Close"])

    df["Date"] = pd.to_datetime(df["Date"], errors="coerce")
    df["Close"] = pd.to_numeric(df["Close"], errors="coerce")
    df = df.dropna(subset=["Date", "Close"]).copy()
    df = df.sort_values("Date").reset_index(drop=True)
    return df

def compute_metrics(df, window):
    df = df.copy()
    if df.empty or "Close" not in df.columns:
        return df

    df["Daily_Return"] = df["Close"].pct_change(fill_method=None)
    df["Volatility"] = df["Daily_Return"].rolling(window).std()

    vmin, vmax = df["Volatility"].min(skipna=True), df["Volatility"].max(skipna=True)
    if pd.isna(vmin) or pd.isna(vmax) or vmin == vmax:
        df["Risk_Score"] = np.nan
    else:
        df["Risk_Score"] = ((df["Volatility"] - vmin) / (vmax - vmin) * 100).clip(0, 100)

    def risk_category(v):
        if pd.isna(v):
            return "Unknown"
        if v < 0.01:
            return "Low"
        if v < 0.03:
            return "Medium"
        return "High"

    df["Risk_Category"] = df["Volatility"].apply(risk_category)

    roll_mean = df["Volatility"].rolling(14).mean()
    roll_std = df["Volatility"].rolling(14).std()
    df["Vol_Spike_Alert"] = df["Volatility"] > (roll_mean + 2 * roll_std)
    df["Price_Drop_Alert"] = df["Daily_Return"] < -0.05

    def explain_row(r):
        if pd.isna(r.get("Volatility", np.nan)) or pd.isna(r.get("Risk_Score", np.nan)):
            return "Not enough data for explanation."
        parts = [f"Risk: {r['Risk_Category']} (Score {r['Risk_Score']:.0f}/100)"]
        if bool(r.get("Vol_Spike_Alert", False)):
            parts.append("Volatility spike detected")
        if bool(r.get("Price_Drop_Alert", False)):
            parts.append("Sudden price drop detected")
        return " | ".join(parts)

    df["Insight"] = df.apply(explain_row, axis=1)
    return df

with st.sidebar:
    st.header("⚙️ Controls")
    start_date = st.date_input("Start Date", value=pd.to_datetime("2022-01-01"))
    window = st.slider("Volatility Window (days)", 7, 30, 14)
    single_coin = st.selectbox("Single Coin", list(coins_map.keys()), index=0)
    compare_coins = st.multiselect(
        "Compare Coins (2–5 recommended)",
        list(coins_map.keys()),
        default=["Bitcoin (BTC)", "Ethereum (ETH)", "Solana (SOL)"]
    )

with tab_main:
    ticker = coins_map[single_coin]
    df_raw = load_data(ticker, start_date)
    df = compute_metrics(df_raw, window)

    base = df.dropna(subset=["Close"]).copy() if not df.empty else pd.DataFrame()
    if base.empty:
        st.error("No data received from Yahoo Finance right now. Try again after a minute, change Start Date, or switch coin.")
        st.stop()

    latest = base.tail(1).iloc[0]
    latest_metrics = df.dropna(subset=["Volatility", "Risk_Score"]).tail(1)

    price = float(latest["Close"])
    ret = float(latest["Daily_Return"]) if "Daily_Return" in df.columns and not pd.isna(latest.get("Daily_Return", np.nan)) else np.nan

    if len(latest_metrics):
        vol = float(latest_metrics["Volatility"].iloc[0])
        risk_score = float(latest_metrics["Risk_Score"].iloc[0])
        risk_level = str(latest_metrics["Risk_Category"].iloc[0])
        reason = str(latest_metrics["Insight"].iloc[0])
    else:
        vol, risk_score, risk_level, reason = np.nan, np.nan, "Unknown", "Not enough data for risk metrics."

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Price", f"{price:,.2f}", f"{ret*100:+.2f}%" if not pd.isna(ret) else None)
    c2.metric("Volatility", f"{vol:.4f}" if not pd.isna(vol) else "N/A")
    c3.metric("Risk Score", f"{risk_score:.0f}/100" if not pd.isna(risk_score) else "N/A")
    c4.metric("Risk Level", risk_level)

    st.info(reason)

    colA, colB = st.columns(2)
    with colA:
        st.subheader("📈 Price Trend")
        st.line_chart(df.set_index("Date")[["Close"]] if not df.empty else pd.DataFrame())
    with colB:
        st.subheader("📉 Volatility Trend")
        st.line_chart(df.set_index("Date")[["Volatility"]] if "Volatility" in df.columns else pd.DataFrame())

    st.subheader("🚨 Recent Alerts")
    if "Vol_Spike_Alert" in df.columns and "Price_Drop_Alert" in df.columns:
        alerts = df[df["Vol_Spike_Alert"] | df["Price_Drop_Alert"]].copy()
        if not alerts.empty:
            alerts["Alert_Type"] = np.where(alerts["Vol_Spike_Alert"], "Volatility Spike", "Price Drop")
            alerts_view = alerts[["Date", "Alert_Type", "Close", "Daily_Return", "Volatility", "Risk_Category"]].tail(15)
            st.dataframe(alerts_view.reset_index(drop=True), use_container_width=True)
        else:
            st.success("No alerts detected in the selected period.")
    else:
        st.info("Alerts will appear after enough data is available.")

with tab_compare:
    if len(compare_coins) < 1:
        st.warning("Select at least one coin in the sidebar to compare.")
    else:
        frames = []
        for name in compare_coins:
            t = coins_map[name]
            d_raw = load_data(t, start_date)
            d = compute_metrics(d_raw, window)
            if not d.empty:
                d["Coin"] = name
                frames.append(d)

        if not frames:
            st.error("No comparison data available right now (Yahoo returned empty). Try again later.")
        else:
            all_df = pd.concat(frames, ignore_index=True)

            summary = all_df.groupby("Coin").agg(
                Avg_Volatility=("Volatility", "mean"),
                Avg_Risk_Score=("Risk_Score", "mean"),
                Latest_Close=("Close", "last")
            ).reset_index()

            def dominant_mode(s):
                m = s.dropna().mode()
                return m.iloc[0] if len(m) else "Unknown"

            summary["Dominant_Risk"] = all_df.groupby("Coin")["Risk_Category"].apply(dominant_mode).values
            summary["Stability_Score"] = (100 - summary["Avg_Risk_Score"]).clip(0, 100)
            summary = summary.sort_values("Stability_Score", ascending=False).reset_index(drop=True)
            summary["Rank_Safest"] = summary.index + 1

            st.subheader("📊 Comparison Summary (Safest → Riskiest)")
            st.dataframe(summary.reset_index(drop=True), use_container_width=True)

            c1, c2 = st.columns(2)
            with c1:
                st.subheader("✅ Top 3 Safest")
                st.dataframe(summary.head(3).reset_index(drop=True), use_container_width=True)
            with c2:
                st.subheader("⚠️ Top 3 Riskiest")
                st.dataframe(summary.sort_values("Avg_Risk_Score", ascending=False).head(3).reset_index(drop=True), use_container_width=True)

with tab_portfolio:
    st.subheader("💼 Portfolio Risk Calculator")
    if len(compare_coins) < 1:
        st.warning("Select coins in sidebar (Compare Coins) to use portfolio feature.")
    else:
        weights = {}
        cols = st.columns(len(compare_coins))
        for i, coin in enumerate(compare_coins):
            with cols[i]:
                weights[coin] = st.slider(f"{coin} weight %", 0, 100, 0)

        total_w = sum(weights.values())
        st.write(f"Total weight: {total_w}%")

        if total_w == 0:
            st.warning("Set at least one coin weight.")
        else:
            frames = []
            for name in compare_coins:
                t = coins_map[name]
                d_raw = load_data(t, start_date)
                d = compute_metrics(d_raw, window)
                if not d.empty:
                    d["Coin"] = name
                    frames.append(d)

            if not frames:
                st.error("Portfolio data unavailable (Yahoo returned empty). Try again later.")
            else:
                all_df = pd.concat(frames, ignore_index=True)

                summary = all_df.groupby("Coin").agg(
                    Avg_Volatility=("Volatility", "mean"),
                    Avg_Risk_Score=("Risk_Score", "mean"),
                ).reset_index()

                w_norm = {k: v / total_w for k, v in weights.items() if v > 0}

                portfolio_risk = 0.0
                portfolio_vol = 0.0
                for coin, w in w_norm.items():
                    row = summary[summary["Coin"] == coin]
                    if len(row):
                        portfolio_risk += float(row["Avg_Risk_Score"].iloc[0]) * w
                        portfolio_vol += float(row["Avg_Volatility"].iloc[0]) * w

                if portfolio_risk >= 70:
                    prisk_level = "High"
                elif portfolio_risk >= 40:
                    prisk_level = "Medium"
                else:
                    prisk_level = "Low"

                c1, c2, c3 = st.columns(3)
                c1.metric("Portfolio Risk Score", f"{portfolio_risk:.1f}/100")
                c2.metric("Portfolio Avg Volatility", f"{portfolio_vol:.4f}")
                c3.metric("Portfolio Risk Level", prisk_level)

                breakdown = pd.DataFrame({
                    "Coin": list(w_norm.keys()),
                    "Weight (normalized)": [round(v, 3) for v in w_norm.values()]
                })
                st.dataframe(breakdown.reset_index(drop=True), use_container_width=True)

with tab_ml:
    st.subheader("🤖 ML Forecast (Next-day Volatility)")
    enable_ml = st.checkbox("Enable Risk Forecast (requires scikit-learn)")

    if enable_ml:
        try:
            from sklearn.linear_model import LinearRegression
            from sklearn.preprocessing import StandardScaler

            if len(compare_coins) < 1:
                st.warning("Select coins in sidebar (Compare Coins) to forecast.")
            else:
                frames = []
                for name in compare_coins:
                    t = coins_map[name]
                    d_raw = load_data(t, start_date)
                    d = compute_metrics(d_raw, window)
                    if not d.empty:
                        d["Coin"] = name
                        frames.append(d)

                if not frames:
                    st.error("No ML data available right now (Yahoo returned empty). Try later.")
                else:
                    all_df = pd.concat(frames, ignore_index=True)

                    ml_frames = []
                    for coin in compare_coins:
                        cdf = all_df[all_df["Coin"] == coin].copy().sort_values("Date")
                        cdf["Vol_Lag1"] = cdf["Volatility"].shift(1)
                        cdf["Ret_Lag1"] = cdf["Daily_Return"].shift(1)
                        cdf["Target_NextVol"] = cdf["Volatility"].shift(-1)
                        cdf = cdf.dropna(subset=["Vol_Lag1", "Ret_Lag1", "Target_NextVol"])
                        if not cdf.empty:
                            cdf["Coin"] = coin
                            ml_frames.append(cdf)

                    if not ml_frames:
                        st.warning("Not enough data for ML forecasting (try earlier start date).")
                    else:
                        ml_df = pd.concat(ml_frames, ignore_index=True)

                        X = ml_df[["Vol_Lag1", "Ret_Lag1"]]
                        y = ml_df["Target_NextVol"]

                        scaler = StandardScaler()
                        Xs = scaler.fit_transform(X)

                        model = LinearRegression()
                        model.fit(Xs, y)

                        ml_df["Predicted_NextVol"] = model.predict(Xs)

                        def pred_risk(v):
                            if pd.isna(v):
                                return "Unknown"
                            if v < 0.01:
                                return "Low"
                            if v < 0.03:
                                return "Medium"
                            return "High"

                        ml_df["Predicted_Risk"] = ml_df["Predicted_NextVol"].apply(pred_risk)

                        forecast = (
                            ml_df.sort_values("Date")
                            .groupby("Coin")
                            .tail(1)[["Coin", "Volatility", "Predicted_NextVol", "Predicted_Risk"]]
                            .reset_index(drop=True)
                        )

                        st.dataframe(forecast.reset_index(drop=True), use_container_width=True)
        except Exception as e:
            st.error(f"ML module error: {e}")
            st.info("Install scikit-learn via requirements.txt and redeploy.")

with tab_data:
    st.subheader("⬇️ Download / Data Preview")
    st.write("Download the processed dataset for the selected single coin.")

    ticker = coins_map[single_coin]
    df_raw = load_data(ticker, start_date)
    df = compute_metrics(df_raw, window)

    if df.empty:
        st.warning("No data available to download right now. Try later.")
    else:
        st.dataframe(df.tail(200).reset_index(drop=True), use_container_width=True)
        st.download_button(
            "Download Processed CSV",
            df.to_csv(index=False),
            file_name=f"{ticker}_risk_processed.csv",
            mime="text/csv"
        )

