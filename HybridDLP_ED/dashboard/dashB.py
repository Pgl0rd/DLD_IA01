import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime
import altair as alt
from streamlit_autorefresh import st_autorefresh

# ================= CONFIG =================
st.set_page_config(
    page_title="Hybrid DLP Security Center",
    page_icon="🛡️",
    layout="wide"
)

# Auto refresh
st_autorefresh(interval=2000, key="refresh")

# ================= CSS =================
st.markdown("""
<style>
div[data-testid="metric-container"] {
    background-color: #f0f2f6;
    border-radius: 10px;
    padding: 10px;
    border: 1px solid #dcdcdc;
}
.main-title {
    font-size: 40px;
    font-weight: bold;
    color: #1E3A8A;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# ================= PATH =================
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "alerts.json")

# ================= LOAD DATA =================
def load_data():
    if not os.path.exists(LOG_FILE):
        st.warning(f"⚠ Log file not found: {LOG_FILE}")
        return pd.DataFrame()

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not data:
            st.warning("⚠ Log file is empty")
            return pd.DataFrame()

        df = pd.DataFrame(data)
        
        # Debug info
        file_mtime = os.path.getmtime(LOG_FILE) if os.path.exists(LOG_FILE) else 0
        file_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
        st.sidebar.text(f"📁 File: {os.path.basename(LOG_FILE)}")
        st.sidebar.text(f"📊 Total rows: {len(df)}")
        st.sidebar.text(f"🕒 Modified: {datetime.fromtimestamp(file_mtime).strftime('%H:%M:%S') if file_mtime > 0 else 'N/A'}")
        st.sidebar.text(f"📦 Size: {file_size:,} bytes")

        if not df.empty:
            # Parse timestamp với format ISO8601 (hỗ trợ nhiều format)
            # Use utc=True to avoid FutureWarning about mixed timezones
            df["timestamp"] = pd.to_datetime(df["timestamp"], format='ISO8601', errors='coerce', utc=True)
            # Remove rows với invalid timestamp
            df = df.dropna(subset=['timestamp'])
            # Ensure timestamp is datetime type
            if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
                df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce', utc=True)
                df = df.dropna(subset=['timestamp'])
            
            # Convert action to lowercase if it exists
            if "action" in df.columns:
                df["action"] = df["action"].str.lower()
            
            # Debug: show actions and risk scores
            if "action" in df.columns:
                st.sidebar.text(f"🔍 Actions: {df['action'].value_counts().to_dict()}")
            if "risk_score" in df.columns:
                st.sidebar.text(f"📈 Risk range: {df['risk_score'].min()}-{df['risk_score'].max()}")

        return df

    except json.JSONDecodeError as e:
        st.error(f"❌ JSON decode error: {e}")
        st.error(f"File: {LOG_FILE}")
        return pd.DataFrame()
    except Exception as e:
        st.error(f"❌ Lỗi đọc log: {e}")
        import traceback
        st.error(f"Traceback: {traceback.format_exc()}")
        return pd.DataFrame()

# ================= SEVERITY =================
def classify_severity(score):
    if score >= 10:
        return "High"
    elif score >= 5:
        return "Medium"
    else:
        return "Low"

# ================= UI =================
st.markdown('<div class="main-title">🛡️ HYBRID DLP - SECURITY CENTER</div>', unsafe_allow_html=True)
st.divider()

df = load_data()

# ================= SIDEBAR =================
st.sidebar.header("🔍 Bộ lọc")

# Risk score range: 0-100 (not 0-20)
risk_range = st.sidebar.slider("Risk Score", 0, 100, (0, 100))

action_filter = st.sidebar.multiselect(
    "Action",
    options=["allowed", "alerted", "blocked"],
    default=["allowed", "alerted", "blocked"]
)

# ================= PROCESS =================
if not df.empty:
    df["severity"] = df["risk_score"].apply(classify_severity)

    df = df[
        df["risk_score"].between(*risk_range) &
        df["action"].isin(action_filter)
    ]

# ================= NO DATA =================
if df.empty:
    st.warning("⚠ Không có dữ liệu sau khi filter")
    st.stop()

# ================= KPI =================
col1, col2, col3, col4 = st.columns(4)

col1.metric("📊 TỔNG SỰ KIỆN", len(df))
col2.metric("✅ LOW", len(df[df["severity"] == "Low"]))
col3.metric("🔥 HIGH", len(df[df["severity"] == "High"]))
col4.metric("🕒 UPDATE", datetime.now().strftime("%H:%M:%S"))

st.divider()

# ================= CHART =================
chart1, chart2, chart3 = st.columns(3)

# ---- TREND ----
with chart1:
    st.subheader("📈 Trend")

    df_chart = df.copy()
    # Ensure timestamp is datetime before using .dt accessor
    if pd.api.types.is_datetime64_any_dtype(df_chart["timestamp"]):
        df_chart["time_group"] = df_chart["timestamp"].dt.floor("min")
        trend_df = df_chart.groupby("time_group").size().reset_index(name="event_count")
        
        chart = alt.Chart(trend_df).mark_area().encode(
            x="time_group:T",
            y="event_count:Q",
            tooltip=["time_group:T", "event_count:Q"]
        )
        st.altair_chart(chart, width='stretch')
    else:
        st.warning("Timestamp column is not datetime type")

# ---- RISK PIE ----
with chart2:
    st.subheader("🍩 Risk Ratio")

    risk_data = df["severity"].value_counts().reset_index()
    risk_data.columns = ["Severity", "Count"]

    pie = alt.Chart(risk_data).mark_arc(innerRadius=50).encode(
        theta="Count",
        color="Severity",
        tooltip=["Severity", "Count"]
    )

    st.altair_chart(pie, width='stretch')

# ---- KEYWORD ----
with chart3:
    st.subheader("🔑 Top Keywords")

    if "keywords" in df.columns:
        kw = df["keywords"].explode().value_counts().head(5).reset_index()
        kw.columns = ["Keyword", "Count"]

        bar = alt.Chart(kw).mark_bar().encode(
            x="Count",
            y=alt.Y("Keyword", sort="-x")
        )

        st.altair_chart(bar, use_container_width=True)

st.divider()

# ================= TABLE =================
st.subheader("🚨 Alerts Log")

st.dataframe(df, width='stretch')

# ================= DEBUG =================
with st.expander("⚙ Debug"):
    st.write("Log path:", LOG_FILE)
    st.write("Total rows loaded:", len(load_data()))
    st.write("Rows after filter:", len(df))
    st.write("Action filter:", action_filter)
    st.write("Risk range:", risk_range)
    if not df.empty:
        st.write("Actions in data:", df["action"].unique().tolist())
        st.write("Risk scores in data:", df["risk_score"].min(), "-", df["risk_score"].max())
