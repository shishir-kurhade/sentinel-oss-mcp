import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime
from sentinel.cache import VectorCache
from sentinel.models import GeminiClient

# Set page config for a premium feel
st.set_page_config(
    page_title="Sentinel Security HUD",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for dark mode "Security HUD" aesthetic
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .metric-card {
        background: #1e2130;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #00d4ff;
    }
    .block-card {
        border-left: 5px solid #ff4b4b;
    }
    .allow-card {
        border-left: 5px solid #2ecc71;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Cache
@st.cache_resource
def get_cache():
    # We need a dummy client for embedding search if we want to add data from UI, 
    # but for dashboard we usually just read logs.
    return VectorCache()

cache = get_cache()

st.title("🛡️ Sentinel Security HUD")
st.subheader("Waterfall Defense Operations Center")

# Sidebar for controls
with st.sidebar:
    st.header("Controls")
    if st.button("🔄 Refresh Data"):
        st.rerun()
    
    st.divider()
    st.info("Sentinel-OSS v0.4.0-dev\nPowered by Google Gemini & LanceDB")

# Fetch Stats
stats = cache.get_analytics_summary()

# Row 1: Metrics
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Total Audits", stats["total_prompts"])
with m2:
    st.metric("Blocked Attempts", stats["blocked_prompts"], delta_color="inverse")
with m3:
    st.metric("Avg Latency", f"{stats.get('avg_latency_ms', 0)}ms")
with m4:
    st.metric("Block Rate", f"{stats['block_rate']*100}%")

# Row 2: Charts & Visuals
c1, c2 = st.columns([2, 1])

with c1:
    st.write("### 🕒 Interaction History")
    logs_data = cache.get_recent_logs(limit=100)
    if logs_data:
        df = pd.DataFrame(logs_data)
        # Select and reorder columns for display
        display_df = df[['timestamp', 'verdict', 'layer', 'latency_ms', 'prompt', 'reason']]
        st.dataframe(
            display_df,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Time"),
                "latency_ms": st.column_config.NumberColumn("Latency (ms)", format="%d"),
                "verdict": st.column_config.TextColumn("Verdict"),
            },
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No audit logs found. Start testing your agent to see data here!")

with c2:
    st.write("### 🎯 Top Block Layer")
    if stats["top_layer"] != "N/A":
        st.success(f"**{stats['top_layer']}** is your most active shield.")
    else:
        st.write("No blocks recorded yet.")

    st.divider()
    st.write("### 🌊 Waterfall Status")
    layers = ["Semantic Cache", "Tiny Guard", "Expert Audit"]
    for i, layer in enumerate(layers):
        status = "🟢 Active"
        st.write(f"**Layer {i+1}: {layer}**")
        st.caption(status)

# Footer
st.divider()
st.caption(f"Last heartbeat: {stats.get('last_updated', 'N/A')}")
