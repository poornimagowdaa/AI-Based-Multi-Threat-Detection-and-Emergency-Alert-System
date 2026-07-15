"""
SmartSurveillance — AI Powered Multi-Threat Detection & Emergency Monitoring System
Single-Page Dashboard | RoadSafe AI Style Layout
"""

import streamlit as st
import sqlite3
import pandas as pd
import json
import os
import glob
import random
import math
import requests as _requests
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import folium
from streamlit_folium import st_folium

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="SmartSurveillance — AI Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
BASE_DIR    = os.path.join(os.path.dirname(__file__), "Dataset")
DB_PATH     = os.path.join(BASE_DIR, "smart_surveillance.db")
RESULTS_DIR = os.path.join(BASE_DIR, "Results")
EVIDENCE_DIR= os.path.join(BASE_DIR, "Evidence")
VIDEOS_DIR  = os.path.join(BASE_DIR, "Videos")
FIRE_JSON   = os.path.join(BASE_DIR, "fire_coordinates.json")
FALL_JSON   = os.path.join(BASE_DIR, "fall_coordinates.json")
VIOLENCE_JSON= os.path.join(BASE_DIR, "violence_coordinates.json")

# ─────────────────────────────────────────────
# CUSTOM CSS  —  RoadSafe-style (light cards, dark header)
# ─────────────────────────────────────────────
st.markdown("""
<style>
/* Hide sidebar toggle & Streamlit chrome */
[data-testid="collapsedControl"] { display: none; }
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 0 1.5rem 2rem !important; max-width: 100% !important; }

/* ── TOP HEADER ── */
.top-header {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    padding: 20px 30px; border-radius: 12px; margin-bottom: 20px;
    display: flex; align-items: center; justify-content: space-between;
}
.header-title { font-size: 26px; font-weight: 700; color: white; margin: 0; }
.header-sub   { font-size: 12px; color: #aaa; margin: 4px 0 0 0; }
.header-live  {
    background: rgba(99,153,34,0.2); border: 1px solid #639922;
    border-radius: 99px; padding: 6px 16px; color: #9fe1cb; font-size: 13px;
}

/* ── SECTION HEADERS ── */
.section-header {
    background: #f0f2f6; border-left: 4px solid #e24b4a;
    padding: 10px 16px; border-radius: 0 8px 8px 0;
    margin: 28px 0 16px 0; font-size: 15px; font-weight: 600; color: #1a1a2e;
}

/* ── KPI CARDS ── */
.kpi-card {
    background: white; border: 1px solid #e8e8e8; border-radius: 12px;
    padding: 16px 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.06);
}
.kpi-number { font-size: 36px; font-weight: 700; margin: 4px 0; }
.kpi-label  { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 0.05em; }

/* ── INFO CARDS ── */
.info-card {
    background: white; border: 1px solid #e8e8e8; border-radius: 10px;
    padding: 12px 14px; box-shadow: 0 1px 4px rgba(0,0,0,0.05); margin-bottom: 8px;
}
.info-card-title { font-size: 11px; color: #888; text-transform: uppercase; margin-bottom: 4px; }
.info-card-value { font-size: 14px; font-weight: 600; color: #1a1a2e; }

/* ── ALERT ITEMS ── */
.alert-sent {
    background: #eaf3de; border-left: 3px solid #639922;
    padding: 10px 14px; border-radius: 0 8px 8px 0;
    margin-bottom: 8px; font-size: 13px; color: #27500a;
}
.alert-call {
    background: #eaf0fb; border-left: 3px solid #185fa5;
    padding: 10px 14px; border-radius: 0 8px 8px 0;
    margin-bottom: 8px; font-size: 13px; color: #0d2e5c;
}
.alert-warn {
    background: #faeeda; border-left: 3px solid #ef9f27;
    padding: 10px 14px; border-radius: 0 8px 8px 0;
    margin-bottom: 8px; font-size: 13px; color: #633806;
}
.alert-fail {
    background: #fde8e8; border-left: 3px solid #e24b4a;
    padding: 10px 14px; border-radius: 0 8px 8px 0;
    margin-bottom: 8px; font-size: 13px; color: #7a1a1a;
}

/* ── PROGRESS BAR ── */
.prog-wrap { margin: 6px 0; }
.prog-label { display: flex; justify-content: space-between; font-size: .8rem; margin-bottom: 4px; }
.prog-bar { height: 8px; border-radius: 4px; background: #e8e8e8; overflow: hidden; }
.prog-fill { height: 100%; border-radius: 4px; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────
# ── Always open a fresh connection per query — cached connections go stale ──
def query_db(sql: str, params=()) -> pd.DataFrame:
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df   = pd.read_sql_query(sql, conn, params=params)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def db_scalar(sql: str, params=(), default=0):
    if not os.path.exists(DB_PATH):
        return default
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute(sql, params)
        row  = cur.fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default


# ─────────────────────────────────────────────
# JSON / CSV HELPERS
# ─────────────────────────────────────────────
def load_json(path: str):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []

def load_severity_xlsx(threat: str) -> dict:
    """
    Reads Results/fire_severity1.csv, fall_severity1.csv, violence_severity1.csv
    Columns are: 'Severity' and 'count'
    Returns dict like: {'Critical': 39, 'Major': 41, 'Minor': 10}
    Returns {} silently if file not found (no warning shown to user).
    """
    fname_map = {
        "fire":     "fire_severity1.csv",
        "fall":     "fall_severity1.csv",
        "violence": "violence_severity1.csv",
    }
    path = os.path.join(RESULTS_DIR, fname_map.get(threat.lower(), ""))
    if not os.path.exists(path):
        return {}   # Silent fallback — no st.warning
    try:
        xdf = pd.read_csv(path)
        # Normalize all column names to lowercase for safe access
        xdf.columns = [c.strip().lower() for c in xdf.columns]
        # columns are now 'severity' and 'count'
        xdf["severity"] = xdf["severity"].str.strip().str.capitalize()
        return dict(zip(xdf["severity"], xdf["count"]))
    except Exception:
        return {}


def _severity_from_db(threat: str) -> dict:
    """
    Counts severity levels directly from the DB (or demo data) for one threat type.
    Safe to call before the global `df` is loaded.
    """
    sub = query_db("""
        SELECT severity_level AS severity
        FROM   events
        WHERE  LOWER(event_type) = LOWER(?)
    """, (threat,))
    if sub.empty:
        # Use demo data as last resort
        demo = demo_incidents()
        sub  = demo[demo["threat_type"].str.lower() == threat.lower()][["severity"]]
    if sub.empty:
        return {"Critical": 0, "Major": 0, "Minor": 0}
    sub["severity"] = sub["severity"].str.strip().str.capitalize()
    vc = sub["severity"].value_counts()
    return {
        "Critical": int(vc.get("Critical", 0)),
        "Major":    int(vc.get("Major",    0)),
        "Minor":    int(vc.get("Minor",    0)),
    }


def get_severity_counts_from_xlsx() -> dict:
    """
    Returns:
    {
      'fire':     {'Critical': 39, 'Major': 41, 'Minor': 10},
      'fall':     {'Critical': 16, 'Major': 44, 'Minor': 19},
      'violence': {'Critical': 64, 'Major': 86, 'Minor': 0},
    }
    Priority: xlsx file → DB → demo data
    """
    result = {}
    for threat in ["fire", "fall", "violence"]:
        counts = load_severity_xlsx(threat)
        if not counts:
            # Fallback: query DB directly (safe before global df is set)
            counts = _severity_from_db(threat)
        result[threat] = counts
    return result


# ─────────────────────────────────────────────
# DEMO DATA FALLBACK
# ─────────────────────────────────────────────
def demo_incidents(n=319):
    random.seed(42)
    types      = ["Fire", "Violence", "Fall"]
    severities = ["Minor", "Major", "Critical"]
    cameras    = [f"CAM-{i:03d}" for i in range(1, 31)]
    locations  = [
        "Block A - Gate 1", "Block B - Corridor", "Parking Lot C",
        "Main Entrance", "Warehouse Zone", "Lobby Floor 2",
        "Exit Gate 4", "Control Room", "Server Hall", "Plaza North",
    ]
    rows = []
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    for i in range(n):
        t   = types[i % 3]
        sev = random.choices(severities, weights=[5, 3, 2])[0]
        dt  = base_time + timedelta(minutes=random.randint(0, 525600))
        rows.append({
            "incident_id":     i + 1,
            "threat_type":     t,
            "severity":        sev,
            "confidence":      round(random.uniform(0.55, 0.99), 3),
            "timestamp":       dt.strftime("%Y-%m-%d %H:%M:%S"),
            "camera_id":       random.choice(cameras),
            "location":        random.choice(locations),
            "latitude":        round(12.9716 + random.uniform(-0.15, 0.15), 6),
            "longitude":       round(77.5946 + random.uniform(-0.15, 0.15), 6),
            "status":          "Active",
            "response_status": "Pending",
        })
    return pd.DataFrame(rows)

def demo_emergency(kind="police", n=8):
    random.seed(hash(kind))
    names = {
        "police":   ["Central Police HQ", "North Division Station", "South Beat Office",
                     "East Zone Station", "West Precinct", "Cyber Crime Unit",
                     "Traffic Control Station", "K9 Unit HQ"],
        "fire":     ["Central Fire Brigade", "North Fire Station", "South Fire Dept",
                     "East Rescue Unit", "West Fire Post", "Industrial Fire Station",
                     "Airport Fire Station", "Chemical Fire Unit"],
        "hospital": ["City General Hospital", "Apollo Medical Center", "Fortis Hospital",
                     "Trauma & Emergency Care", "St. John's Hospital", "Manipal Hospital",
                     "NIMHANS Hospital", "Sparsh Hospital"],
    }
    rows = []
    for name in names.get(kind, [])[:n]:
        rows.append({
            "name":      name,
            "phone":     f"+91-80-{random.randint(20000000, 29999999)}",
            "address":   f"{random.randint(1, 200)} Main Road, Bangalore",
            "latitude":  round(12.9716 + random.uniform(-0.2, 0.2), 6),
            "longitude": round(77.5946 + random.uniform(-0.2, 0.2), 6),
        })
    return pd.DataFrame(rows)

def demo_alerts(n=20):
    random.seed(7)
    receiver_types = ["Family", "Police", "Fire Station", "Hospital"]
    statuses       = ["sent", "sent", "sent", "sent"]  # DB only has 'sent'
    rows = []
    base_time = datetime.now() - timedelta(hours=6)
    for i in range(n):
        rows.append({
            "alert_id":      i + 1,
            "incident_ref":  random.randint(1, 319),
            "event_type":    random.choice(["Fire", "Fall", "Violence"]),
            "severity_level":random.choice(["Minor", "Major", "Critical"]),
            "sent_to":       f"Contact {i+1}",
            "receiver_type": random.choice(receiver_types),
            "contact_number":f"+91-{random.randint(7000000000, 9999999999)}",
            "alert_message": "Threat detected at surveillance zone.",
            "status":        "sent",
            "timestamp":     (base_time + timedelta(minutes=i * 18)).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────
# DATA LOADERS
# ─────────────────────────────────────────────
def get_incidents() -> pd.DataFrame:
    """
    Fetches from: events
    DB columns  : incident_id, video_name, event_type, frame_number, timestamp,
                  location, latitude, longitude, severity_level, confidence_score
    Aliased to  : threat_type, severity, confidence  (dashboard names)

    FIX: DB primary key is 'incident_id' (NOT 'event_id').
         Alias event_type → threat_type, severity_level → severity,
         confidence_score → confidence.
    """
    df = query_db("""
        SELECT
            incident_id,
            event_type       AS threat_type,
            severity_level   AS severity,
            confidence_score AS confidence,
            timestamp,
            video_name       AS camera_id,
            location,
            latitude,
            longitude
        FROM events
        ORDER BY timestamp DESC
    """)
    if df.empty:
        df = demo_incidents()
    df.columns = [c.lower() for c in df.columns]
    # ── Normalize casing so all filters work reliably ──
    if "severity" in df.columns:
        df["severity"] = df["severity"].str.strip().str.capitalize()   # critical→Critical
    if "threat_type" in df.columns:
        df["threat_type"] = df["threat_type"].str.strip().str.capitalize()  # fire→Fire
    return df


def get_emergency(kind: str) -> pd.DataFrame:
    """
    Fetches from : police_stations | fire_stations | hospitals
    DB columns (police/fire): station_id, station_name, location, latitude, longitude,
                              contact_number, email
    DB columns (hospital)   : hospital_id, hospital_name, location, latitude, longitude,
                              contact_number, email, ambulance_available
    Aliased to  : name, phone, address
    """
    col_maps = {
        "police":   ("police_stations", "station_name",  "contact_number", "location"),
        "fire":     ("fire_stations",   "station_name",  "contact_number", "location"),
        "hospital": ("hospitals",       "hospital_name", "contact_number", "location"),
    }
    table, name_col, phone_col, addr_col = col_maps.get(
        kind, ("police_stations", "station_name", "contact_number", "location")
    )
    df = query_db(f"""
        SELECT
            {name_col}  AS name,
            {phone_col} AS phone,
            {addr_col}  AS address,
            latitude,
            longitude
        FROM {table}
    """)
    if df.empty:
        df = demo_emergency(kind)
    df.columns = [c.lower() for c in df.columns]
    return df


def get_alerts() -> pd.DataFrame:
    """
    Fetches from : alerts
    DB columns   : alert_id, incident_id, event_type, severity_level, sent_to,
                   receiver_type, contact_number, alert_message, status, timestamp, alert_mode

    FIX: Old code queried 'event_id', 'alert_type', 'recipient', 'delivery_status'
         — none of these columns exist in the DB.
         Correct column names used below.
    """
    df = query_db("""
        SELECT
            alert_id,
            incident_id      AS incident_ref,
            event_type,
            severity_level,
            sent_to,
            receiver_type,
            contact_number,
            alert_message,
            status,
            timestamp
        FROM alerts
        ORDER BY timestamp DESC
    """)
    if df.empty:
        df = demo_alerts()
    df.columns = [c.lower() for c in df.columns]
    return df


def get_coordinates(json_path: str, threat_type: str) -> list:
    """
    Primary  : loads from JSON file if it exists and is valid.
    Fallback : queries events table, filters by event_type (aliased as threat_type).
    Returns a plain Python list of dicts with keys:
        latitude, longitude, threat_id, severity, timestamp, confidence
    """
    data = load_json(json_path)
    if data:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in data:
                if isinstance(data[key], list):
                    return data[key]
    # DB fallback
    df  = get_incidents()
    sub = df[df["threat_type"].str.lower() == threat_type.lower()]
    return [
        {
            "latitude":   r.get("latitude",    12.97),
            "longitude":  r.get("longitude",   77.59),
            "threat_id":  r.get("incident_id", "N/A"),
            "severity":   r.get("severity",    "N/A"),
            "timestamp":  r.get("timestamp",   "N/A"),
            "confidence": r.get("confidence",  0),
        }
        for _, r in sub.iterrows()
    ]

# ─────────────────────────────────────────────
# MAP HELPERS
# ─────────────────────────────────────────────
def make_base_map(lat=12.9716, lon=77.5946, zoom=11) -> folium.Map:
    return folium.Map(location=[lat, lon], zoom_start=zoom, tiles="OpenStreetMap")

def add_threat_markers(fmap, coords, color, threat_type):
    folium_color = {"#ff2d2d": "red", "#ff8c00": "orange", "#00ff88": "green"}.get(color, "blue")
    for pt in coords:
        lat = pt.get("latitude", pt.get("lat", 12.97))
        lon = pt.get("longitude", pt.get("lon", 77.59))
        popup_html = f"""
        <div style='font-family:Arial;font-size:11px;min-width:180px;'>
          <b style='color:{color};'>{threat_type.upper()} THREAT</b><br>
          <b>ID:</b> {pt.get('threat_id','N/A')}<br>
          <b>Severity:</b> {pt.get('severity','N/A')}<br>
          <b>Time:</b> {pt.get('timestamp','N/A')}<br>
          <b>Confidence:</b> {pt.get('confidence','N/A')}<br>
          <b>Lat:</b> {lat} | <b>Lon:</b> {lon}
        </div>"""
        folium.Marker(
            location=[lat, lon],
            tooltip=folium.Tooltip(f"{threat_type} — {pt.get('severity','?')}", sticky=True),
            popup=folium.Popup(popup_html, max_width=250),
            icon=folium.Icon(color=folium_color, icon="map-marker", prefix="fa"),
        ).add_to(fmap)

def add_emergency_markers(fmap, df_em, color, kind):
    folium_color = {"#0d8fff": "blue", "#ff2d2d": "red", "#00ff88": "green"}.get(color, "blue")
    for _, r in df_em.iterrows():
        lat = float(r.get("latitude", 12.97))
        lon = float(r.get("longitude", 77.59))
        popup_html = f"""
        <div style='font-family:Arial;font-size:11px;min-width:180px;'>
          <b style='color:{color};'>{kind.upper()}</b><br>
          <b>Name:</b> {r.get('name','N/A')}<br>
          <b>Phone:</b> {r.get('phone', r.get('contact','N/A'))}<br>
          <b>Address:</b> {r.get('address','N/A')}
        </div>"""
        folium.Marker(
            location=[lat, lon],
            tooltip=folium.Tooltip(r.get("name", kind), sticky=True),
            popup=folium.Popup(popup_html, max_width=250),
            icon=folium.Icon(color=folium_color, icon="info-sign"),
        ).add_to(fmap)


# ─────────────────────────────────────────────
# LOAD DATA ONCE
# ─────────────────────────────────────────────
df       = get_incidents()
alert_df = get_alerts()

# ── Severity counts — from xlsx files (source of truth) ──
_sev = get_severity_counts_from_xlsx()



fire_critical = _sev["fire"].get("Critical", 0)
fire_major    = _sev["fire"].get("Major",    0)
fire_minor    = _sev["fire"].get("Minor",    0)
fall_critical = _sev["fall"].get("Critical", 0)
fall_major    = _sev["fall"].get("Major",    0)
fall_minor    = _sev["fall"].get("Minor",    0)
viol_critical = _sev["violence"].get("Critical", 0)
viol_major    = _sev["violence"].get("Major",    0)
viol_minor    = _sev["violence"].get("Minor",    0)

total    = fire_critical + fire_major + fire_minor + fall_critical + fall_major + fall_minor + viol_critical + viol_major + viol_minor
critical = fire_critical + fall_critical + viol_critical
major    = fire_major    + fall_major    + viol_major
minor    = fire_minor    + fall_minor    + viol_minor
fire_c   = fire_critical + fire_major + fire_minor
viol_c   = viol_critical + viol_major + viol_minor
fall_c   = fall_critical + fall_major + fall_minor


# ═══════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════
st.markdown(f"""
<div class="top-header">
    <div>
        <p class="header-title">🛡️ SmartSurveillance — AI Threat Detection System</p>
        <p class="header-sub">Multi-Threat Detection &nbsp;·&nbsp; Fire | Violence | Fall &nbsp;·&nbsp; Bengaluru Surveillance Network</p>
    </div>
    <div class="header-live">● &nbsp; System Live &nbsp;|&nbsp; {datetime.now().strftime('%d %b %Y &nbsp;&nbsp; %H:%M:%S')}</div>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# 1. KPI METRICS
# ═══════════════════════════════════════════════════════
st.markdown('<div class="section-header">📊 Live Metrics</div>', unsafe_allow_html=True)

# Source of truth: xlsx severity files (fire_severity1, fall_severity1, violence_severity1)
k1, k2, k3, k4 = st.columns(4)
for col, label, value, color in zip(
    [k1, k2, k3, k4],
    ["Total Incidents", "🔴 Critical", "🟠 Major", "🟢 Minor"],
    [total, critical, major, minor],
    ["#1a1a2e", "#e24b4a", "#ef9f27", "#639922"],
):
    col.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">{label}</div>
        <div class="kpi-number" style="color:{color}">{value}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# 2. SEVERITY ASSESSMENT
# ═══════════════════════════════════════════════════════
st.markdown('<div class="section-header">⚠️ Severity Assessment</div>', unsafe_allow_html=True)

sv1, sv2, sv3 = st.columns([1, 0.05, 2])

with sv1:
    for level, color, emoji in [("Critical","#e24b4a","🔴"), ("Major","#ef9f27","🟠"), ("Minor","#639922","🟢")]:
        n   = {"Critical": critical, "Major": major, "Minor": minor}.get(level, 0)
        pct = round(n / max(total, 1) * 100, 1)
        st.markdown(f"""
        <div class="info-card" style="border-left:4px solid {color}">
            <div class="info-card-title">{emoji} {level}</div>
            <div class="info-card-value" style="color:{color}">{n} incidents &nbsp;·&nbsp; {pct}%</div>
        </div>""", unsafe_allow_html=True)

with sv3:
    if not df.empty and "severity" in df.columns:
        sev_filter = st.multiselect(
            "Filter by severity",
            ["Critical", "Major", "Minor"],
            default=["Critical", "Major", "Minor"],
            key="sev_filter",
        )
        # case-insensitive filter
        filtered_sev = df[df["severity"].str.strip().str.capitalize().isin(sev_filter)]
        show_cols = [c for c in ["incident_id","threat_type","severity","confidence","timestamp","camera_id","location"]
                     if c in filtered_sev.columns]
        st.dataframe(filtered_sev[show_cols].head(20).reset_index(drop=True),
                     use_container_width=True, hide_index=True, height=220)


# ═══════════════════════════════════════════════════════
# 3. THREAT DISTRIBUTION CHARTS
# ═══════════════════════════════════════════════════════
st.markdown('<div class="section-header">📈 Threat Distribution & Timeline</div>', unsafe_allow_html=True)

ch1, ch2, ch3 = st.columns([1, 1, 1.5])

with ch1:
    st.markdown("**Threat Type**")
    if "threat_type" in df.columns:
        tc = df["threat_type"].value_counts().reset_index()
        tc.columns = ["Type", "Count"]
    else:
        tc = pd.DataFrame({"Type": ["Fire", "Violence", "Fall"], "Count": [107, 106, 106]})
    fig = px.pie(tc, names="Type", values="Count",
                 color="Type",
                 color_discrete_map={"Fire": "#e24b4a", "Violence": "#ef9f27", "Fall": "#639922"},
                 hole=0.5)
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#1a1a2e", margin=dict(t=10, b=10, l=10, r=10),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

with ch2:
    st.markdown("**Severity Breakdown**")
    if "severity" in df.columns:
        sc = df["severity"].value_counts().reset_index()
        sc.columns = ["Severity", "Count"]
    else:
        sc = pd.DataFrame({"Severity": ["Minor", "Major", "Critical"], "Count": [160, 100, 59]})
    fig2 = px.bar(sc, x="Severity", y="Count", color="Severity",
                  color_discrete_map={"Critical": "#e24b4a", "Major": "#ef9f27", "Minor": "#639922"},
                  text="Count")
    fig2.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#1a1a2e", showlegend=False,
        xaxis=dict(showgrid=False), yaxis=dict(showgrid=False),
        margin=dict(t=10, b=10, l=10, r=10),
    )
    fig2.update_traces(textposition="outside", marker_line_width=0)
    st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

with ch3:
    st.markdown("**Incident Timeline**")
    if "timestamp" in df.columns:
        df["date"] = pd.to_datetime(df["timestamp"], errors="coerce").dt.date
        timeline = df.groupby(["date", "threat_type"]).size().reset_index(name="count")
        fig3 = px.line(timeline, x="date", y="count", color="threat_type",
                       color_discrete_map={"Fire": "#e24b4a", "Violence": "#ef9f27", "Fall": "#639922"})
        fig3.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#1a1a2e", showlegend=True,
            xaxis=dict(showgrid=False), yaxis=dict(showgrid=True, gridcolor="#e8e8e8"),
            margin=dict(t=10, b=10, l=10, r=10),
            legend=dict(bgcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})


# ═══════════════════════════════════════════════════════
# 4. LIVE INCIDENT MAP
# ═══════════════════════════════════════════════════════
import random as _random
 
st.markdown('<div class="section-header">🗺️ Live Incident Map — All Threats</div>', unsafe_allow_html=True)
 
def load_map_events() -> pd.DataFrame:
    try:
        df_map = query_db("""
            SELECT
                incident_id,
                event_type       AS threat_type,
                severity_level   AS severity,
                confidence_score AS confidence,
                timestamp,
                location,
                latitude,
                longitude
            FROM events
            WHERE latitude  IS NOT NULL
              AND longitude IS NOT NULL
        """)
        if df_map.empty:
            return df[["incident_id","threat_type","severity","confidence",
                        "timestamp","location","latitude","longitude"]].dropna(
                            subset=["latitude","longitude"])
        if "threat_type" in df_map.columns:
            df_map["threat_type"] = df_map["threat_type"].str.strip().str.capitalize()
        if "severity" in df_map.columns:
            df_map["severity"] = df_map["severity"].str.strip().str.capitalize()
        return df_map
    except Exception:
        return df[["incident_id","threat_type","severity","confidence",
                   "timestamp","location","latitude","longitude"]].dropna(
                       subset=["latitude","longitude"])
 
map_raw = load_map_events()
 
THREAT_FOLIUM = {"Fire": "darkred", "Violence": "darkblue", "Fall": "purple"}
THREAT_HEX    = {"Fire": "#b91c1c", "Violence": "#1e40af", "Fall": "#7c3aed"}
 
SEVERITY_COLOR = {
    "Critical": "#dc2626",
    "Major":    "#d97706",
    "Minor":    "#16a34a",
}
 
def jitter(val, amount=0.0004):
    """Slightly offset repeated coordinates so all pins are individually visible."""
    return float(val) + _random.uniform(-amount, amount)
 
if not map_raw.empty:
 
    # ── Legend + filter checkboxes ──
    leg_c1, leg_c2, leg_c3, leg_c4 = st.columns([1, 1, 1, 4])
    with leg_c1:
        st.markdown(
            '<div style="display:flex;align-items:center;gap:8px;">'
            '<span style="display:inline-block;width:14px;height:14px;'
            'background:#b91c1c;border-radius:50%;"></span>'
            '<b style="color:#b91c1c;">Fire</b></div>',
            unsafe_allow_html=True
        )
        show_fire = st.checkbox("Show Fire", value=True, key="lmap_fire")
    with leg_c2:
        st.markdown(
            '<div style="display:flex;align-items:center;gap:8px;">'
            '<span style="display:inline-block;width:14px;height:14px;'
            'background:#1e40af;border-radius:50%;"></span>'
            '<b style="color:#1e40af;">Violence</b></div>',
            unsafe_allow_html=True
        )
        show_violence = st.checkbox("Show Violence", value=True, key="lmap_violence")
    with leg_c3:
        st.markdown(
            '<div style="display:flex;align-items:center;gap:8px;">'
            '<span style="display:inline-block;width:14px;height:14px;'
            'background:#7c3aed;border-radius:50%;"></span>'
            '<b style="color:#7c3aed;">Fall</b></div>',
            unsafe_allow_html=True
        )
        show_fall = st.checkbox("Show Fall", value=True, key="lmap_fall")
 
    threat_live = []
    if show_fire:     threat_live.append("Fire")
    if show_violence: threat_live.append("Violence")
    if show_fall:     threat_live.append("Fall")
 
    map_df_f = map_raw[map_raw["threat_type"].isin(threat_live)] if threat_live else map_raw
 
    fire_n     = len(map_raw[map_raw["threat_type"] == "Fire"])
    violence_n = len(map_raw[map_raw["threat_type"] == "Violence"])
    fall_n     = len(map_raw[map_raw["threat_type"] == "Fall"])
    st.caption(
        f"Showing **{len(map_df_f)}** of **{len(map_raw)}** incidents — "
        f"🔴 Fire: {fire_n} | 🔵 Violence: {violence_n} | 🟣 Fall: {fall_n}"
    )
 
    # ── Build map — individual pins with stable jitter ──
    m = folium.Map(
        location=[map_raw["latitude"].mean(), map_raw["longitude"].mean()],
        zoom_start=13,
        tiles="OpenStreetMap",
    )
 
    for _, row in map_df_f.iterrows():
        threat     = str(row.get("threat_type", "Unknown"))
        severity   = str(row.get("severity", "Minor"))       # FIX: was undefined as `level`
        confidence = float(row.get("confidence", 0))
        sev_color  = SEVERITY_COLOR.get(severity, "#16a34a")
 
        # Stable jitter — seeded by incident_id so pins don't jump on re-render
        _random.seed(int(row.get("incident_id", 0)))
        lat = jitter(row["latitude"])
        lon = jitter(row["longitude"])
 
        tip = f"""
<div style="font-family:Arial;min-width:220px;max-width:290px;
            padding:5px;max-height:160px;overflow-y:auto;">
    <div style="font-size:13px;font-weight:700;
                color:{THREAT_HEX.get(threat,'#333')};margin-bottom:3px;">
        🛡️ {threat} Incident
    </div>
    <hr style="margin:3px 0;border-color:#ddd;">
    <div style="font-size:11px;line-height:1.6;">
        <b>ID:</b> {row.get('incident_id', '—')}<br>
        <b>Address:</b> {row.get('location', '—')}<br>
        <b>Lat:</b> {round(float(row['latitude']),  5)} &nbsp;
        <b>Lon:</b> {round(float(row['longitude']), 5)}<br>
        <b>Severity:</b>
        <span style="font-size:13px;font-weight:800;color:{sev_color};">
            ● {severity}
        </span><br>
        <b>Time:</b> {row.get('timestamp', '—')}<br>
        <b>Confidence:</b> {confidence:.3f}
    </div>
</div>"""
 
        folium.Marker(
            location=[lat, lon],
            tooltip=folium.Tooltip(tip, sticky=True),
            popup=folium.Popup(tip, max_width=300),
            icon=folium.Icon(
                color=THREAT_FOLIUM.get(threat, "blue"),
                icon_color="white",
                icon="map-marker",
                prefix="fa",
            ),
        ).add_to(m)
 
    st_folium(m, use_container_width=True, height=500, returned_objects=[])
 
else:
    st.warning("No events found. Check DB path.")

# ═══════════════════════════════════════════════════════
# 5. THREAT-SPECIFIC MAPS  (Fire | Fall | Violence)
# ═══════════════════════════════════════════════════════
import random as _random

st.markdown('<div class="section-header">🔥⚡🧍 Threat-Specific Maps</div>', unsafe_allow_html=True)

SEVERITY_FOLIUM = {
    "Critical": "red",
    "Major":    "orange",
    "Minor":    "green",
}

SEVERITY_HEX = {
    "Critical": "#dc2626",
    "Major":    "#d97706",
    "Minor":    "#16a34a",
}

THREAT_HEX = {
    "Fire":     "#b91c1c",
    "Violence": "#1e40af",
    "Fall":     "#7c3aed",
}

# ── Severity filter (shared across all 3 maps) ──
st.markdown("**Filter by Severity:**")
sev_c1, sev_c2, sev_c3, sev_c4 = st.columns([1, 1, 1, 5])
with sev_c1:
    show_critical = st.checkbox("🔴 Critical", value=True, key="ts_critical")
with sev_c2:
    show_major    = st.checkbox("🟠 Major",    value=True, key="ts_major")
with sev_c3:
    show_minor    = st.checkbox("🟢 Minor",    value=True, key="ts_minor")

active_severities = []
if show_critical: active_severities.append("Critical")
if show_major:    active_severities.append("Major")
if show_minor:    active_severities.append("Minor")

tm1, tm2, tm3 = st.columns(3)

for col_widget, (threat, threat_hex) in zip(
    [tm1, tm2, tm3],
    [
        ("Fire",     "#b91c1c"),
        ("Violence", "#1e40af"),
        ("Fall",     "#7c3aed"),
    ],
):
    with col_widget:

        # ── Header + severity legend ──
        st.markdown(f"""
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
            <b style="color:{threat_hex};font-size:15px;">{threat} Incidents</b>
            <span style="font-size:11px;">
                <span style="color:#dc2626;">● Critical</span> &nbsp;
                <span style="color:#d97706;">● Major</span> &nbsp;
                <span style="color:#16a34a;">● Minor</span>
            </span>
        </div>""", unsafe_allow_html=True)

        # ── Pull from map_raw already loaded from DB ──
        sub_df = map_raw[map_raw["threat_type"].str.lower() == threat.lower()].copy()

        # ── Apply severity filter ──
        if active_severities:
            sub_df = sub_df[sub_df["severity"].isin(active_severities)]

        # ── Severity counts (from full unfiltered threat data for reference) ──
        full_sub = map_raw[map_raw["threat_type"].str.lower() == threat.lower()]
        crit_n   = len(full_sub[full_sub["severity"] == "Critical"])
        major_n  = len(full_sub[full_sub["severity"] == "Major"])
        minor_n  = len(full_sub[full_sub["severity"] == "Minor"])
        st.caption(
            f"Showing: {len(sub_df)} / Total: {len(full_sub)}  —  "
            f"🔴 Critical: {crit_n}  |  "
            f"🟠 Major: {major_n}  |  "
            f"🟢 Minor: {minor_n}"
        )

        # ── Build map ──
        center_lat = full_sub["latitude"].mean()  if not full_sub.empty else 12.9716
        center_lon = full_sub["longitude"].mean() if not full_sub.empty else 77.5946

        m = folium.Map(
            location=[center_lat, center_lon],
            zoom_start=11,
            tiles="OpenStreetMap",
        )

        for _, row in sub_df.iterrows():
            severity   = str(row.get("severity", "Minor"))
            confidence = float(row.get("confidence", 0))
            pin_color  = SEVERITY_FOLIUM.get(severity, "blue")
            sev_color  = SEVERITY_HEX.get(severity, "#16a34a")

            # Stable jitter per incident_id
            _random.seed(int(row.get("incident_id", 0)))
            lat = float(row["latitude"])  + _random.uniform(-0.0004, 0.0004)
            lon = float(row["longitude"]) + _random.uniform(-0.0004, 0.0004)

            tip = f"""
<div style="font-family:Arial;min-width:220px;max-width:290px;
            padding:5px;max-height:160px;overflow-y:auto;">
    <div style="font-size:13px;font-weight:700;
                color:{THREAT_HEX.get(threat,'#333')};margin-bottom:3px;">
        🛡️ {threat} Incident
    </div>
    <hr style="margin:3px 0;border-color:#ddd;">
    <div style="font-size:11px;line-height:1.6;">
        <b>ID:</b> {row.get('incident_id', '—')}<br>
        <b>Address:</b> {row.get('location', '—')}<br>
        <b>Lat:</b> {round(float(row['latitude']),  5)} &nbsp;
        <b>Lon:</b> {round(float(row['longitude']), 5)}<br>
        <b>Severity:</b>
        <span style="font-size:13px;font-weight:800;color:{sev_color};">
            ● {severity}
        </span><br>
        <b>Time:</b> {row.get('timestamp', '—')}<br>
        <b>Confidence:</b> {confidence:.3f}
    </div>
</div>"""

            folium.Marker(
                location=[lat, lon],
                tooltip=folium.Tooltip(tip, sticky=True),
                popup=folium.Popup(tip, max_width=320),
                icon=folium.Icon(
                    color=pin_color,
                    icon_color="white",
                    icon="map-marker",
                    prefix="fa",
                ),
            ).add_to(m)

        st_folium(m, height=400, use_container_width=True, returned_objects=[])
        
# ═══════════════════════════════════════════════════════
# 6. EMERGENCY RESPONSE MAPS  (Police | Fire Stn | Hospital)
# ═══════════════════════════════════════════════════════
import random as _random

st.markdown('<div class="section-header">🚔🚒🏥 Emergency Response Maps</div>', unsafe_allow_html=True)

def _haversine_km(lat1, lon1, lat2, lon2):
    """Fast haversine distance in km (no API call needed)."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat/2)**2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon/2)**2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

def load_emergency_nearby(table: str, ref_lat: float, ref_lon: float, top_n: int = 10) -> pd.DataFrame:
    """
    Load all rows from table, compute haversine dist to (ref_lat, ref_lon),
    sort nearest-first, return top_n rows with _dist_km column.
    Falls back to demo data if DB is empty.
    """
    df_em = query_db(f"SELECT * FROM {table}")
    if df_em.empty:
        kind = {"police_stations": "police", "fire_stations": "fire",
                "hospitals": "hospital"}.get(table, "police")
        df_em = demo_emergency(kind)
    df_em.columns = [c.lower() for c in df_em.columns]
    lc = next((c for c in ["latitude", "lat"] if c in df_em.columns), None)
    oc = next((c for c in ["longitude", "lon", "lng"] if c in df_em.columns), None)
    if lc and oc:
        df_em["_dist_km"] = df_em.apply(
            lambda r: _haversine_km(ref_lat, ref_lon, float(r[lc]), float(r[oc])),
            axis=1,
        )
        df_em = df_em.sort_values("_dist_km").head(top_n).reset_index(drop=True)
    return df_em

# Reference centre for Section 6 = mean of all incidents
_area_lat = float(df["latitude"].mean())  if "latitude"  in df.columns and not df.empty else 12.9716
_area_lon = float(df["longitude"].mean()) if "longitude" in df.columns and not df.empty else 77.5946

EMERGENCY_CONFIG = [
    {"table": "police_stations", "title": "🚔 POLICE STATION",
     "title_color": "#0d6efd", "label": "🚔 Police Stations",
     "pin_color": "blue",  "label_color": "#0d6efd", "top_n": 50},
    {"table": "fire_stations",   "title": "🚒 FIRE STATION",
     "title_color": "#e24b4a", "label": "🚒 Fire Stations",
     "pin_color": "red",   "label_color": "#e24b4a", "top_n": 40},
    {"table": "hospitals",       "title": "🏥 HOSPITAL",
     "title_color": "#16a34a", "label": "🏥 Hospitals",
     "pin_color": "green", "label_color": "#16a34a", "top_n": 50},
]

em1, em2, em3 = st.columns(3)

for col_widget, cfg in zip([em1, em2, em3], EMERGENCY_CONFIG):
    with col_widget:
        # ── Heading in service-specific colour ──
        st.markdown(
            f'<div style="font-size:13px;font-weight:800;color:{cfg["label_color"]};'
            f'border-left:4px solid {cfg["label_color"]};padding-left:8px;margin-bottom:8px;">'
            f'{cfg["label"]}</div>',
            unsafe_allow_html=True,
        )

        df_em = load_emergency_nearby(cfg["table"], _area_lat, _area_lon, top_n=cfg["top_n"])

        if df_em.empty:
            st.warning(f"No data in `{cfg['table']}`.")
            continue

        def _col(d, *cands):
            for c in cands:
                if c in d.columns:
                    return c
            return None

        name_col  = _col(df_em, "name", "station_name", "hospital_name", "facility_name")
        addr_col  = _col(df_em, "address", "location", "addr")
        lat_col   = _col(df_em, "latitude", "lat")
        lon_col   = _col(df_em, "longitude", "lon", "lng")
        phone_col = _col(df_em, "phone", "phone_number", "contact", "contact_number")
        email_col = _col(df_em, "email", "email_address")

        # Centre map on nearest location (already sorted)
        center_lat = float(df_em.iloc[0][lat_col]) if lat_col else _area_lat
        center_lon = float(df_em.iloc[0][lon_col]) if lon_col else _area_lon

        m = folium.Map(location=[center_lat, center_lon], zoom_start=11, tiles="OpenStreetMap")

        for rank, (_, row) in enumerate(df_em.iterrows(), start=1):
            lat      = float(row[lat_col])   if lat_col   else 0.0
            lon      = float(row[lon_col])   if lon_col   else 0.0
            name     = row[name_col]          if name_col  else "—"
            addr     = row[addr_col]          if addr_col  else "—"
            phone    = row[phone_col]         if phone_col else "—"
            email    = row[email_col]         if email_col else "—"
            dist_km  = row.get("_dist_km", None)
            dist_str = f"{dist_km:.2f} km"   if dist_km is not None else "—"

            if "POLICE" in cfg["title"]:
                name_label = "Police Station"
            elif "FIRE" in cfg["title"]:
                name_label = "Fire Station"
            else:
                name_label = "Hospital"

            tip = f"""
            <div style="font-family:Arial;width:310px;padding:8px 14px;
                        background:#fff;border-radius:8px;color:#222;
                        box-sizing:border-box;word-wrap:break-word;">
                <div style="font-size:13px;font-weight:900;color:{cfg['title_color']};
                            margin-bottom:4px;">#{rank} {cfg['title']}</div>
                <hr style="margin:3px 0;border-color:#eee;">
                <table style="width:100%;font-size:11px;line-height:1.7;
                              border-collapse:collapse;">
                    <tr><td style="color:#555;padding-right:8px;white-space:nowrap;">
                        <b>{name_label}:</b></td>
                        <td style="color:#111;word-break:break-word;">{name}</td></tr>
                    <tr><td style="color:#555;padding-right:8px;white-space:nowrap;vertical-align:top;">
                        <b>Address:</b></td>
                        <td style="color:#111;white-space:normal;">{addr}</td></tr>
                    <tr><td style="color:#555;padding-right:8px;"><b>Lat:</b></td>
                        <td style="color:#111;">{round(lat,5)}</td></tr>
                    <tr><td style="color:#555;padding-right:8px;"><b>Lon:</b></td>
                        <td style="color:#111;">{round(lon,5)}</td></tr>
                    <tr><td style="color:#555;padding-right:8px;"><b>Phone:</b></td>
                        <td style="color:#111;">{phone}</td></tr>
                    <tr><td style="color:#555;padding-right:8px;"><b>Email:</b></td>
                        <td style="color:#111;word-break:break-word;">{email}</td></tr>
                    <tr><td style="color:#555;padding-right:8px;"><b>🛣️ Dist:</b></td>
                        <td style="color:{cfg['title_color']};font-weight:700;">{dist_str}</td></tr>
                </table>
            </div>"""

            folium.Marker(
                location=[lat, lon],
                tooltip=folium.Tooltip(tip, sticky=True),
                popup=folium.Popup(tip, max_width=330),
                icon=folium.Icon(color=cfg["pin_color"], icon_color="white",
                                 icon="map-marker", prefix="fa"),
            ).add_to(m)

        st.caption(f"Showing {len(df_em)} nearest | sorted by distance from incident zone")
        st_folium(m, height=400, use_container_width=True, returned_objects=[])


# ═══════════════════════════════════════════════════════
# 7. VIDEO ANALYSIS  (Live Monitoring)
# ═══════════════════════════════════════════════════════
import glob as _glob
import re
import base64
 
VIDEOS_DIR   = os.path.join(BASE_DIR, "Videos")
EVIDENCE_DIR = os.path.join(BASE_DIR, "Evidence")

THREAT_VIDEO_FOLDER = {
    "Fire":     "Fire Dataset",
    "Violence": "Violence Dataset",
    "Fall":     "Fall Dataset",
}

THREAT_EVIDENCE_FOLDER = {
    "Fire":     "fire_timestamped",
    "Violence": "violence_timestamped",
    "Fall":     "Fall_timestamped",
}

# ── Natural sort: fire_2 before fire_10 ──
def _natural_key(path):
    name  = os.path.splitext(os.path.basename(path))[0]
    parts = re.split(r'(\d+)', name)
    return [int(p) if p.isdigit() else p.lower() for p in parts]

# ── Evidence subfolders match video name exactly:
#    fire_1.mp4 → fire_1/   fall_1.mp4 → fall_1/   fight_1.mp4 → fight_1/ ──
def _evidence_subfolder(vid_name: str) -> str:
    return os.path.splitext(os.path.basename(vid_name))[0]  # strip path + ext only
 
st.markdown('<div class="section-header">📹 Video Analysis & Live Monitoring</div>',
            unsafe_allow_html=True)
 
# ── CSS: reduced video height ──
# ── CSS: force video height ──
st.markdown("""
<style>
/* Target every possible Streamlit video wrapper */
div[data-testid="stVideo"],
div[data-testid="stVideo"] > div,
div[data-testid="stVideo"] > div > div {
    max-height: 220px !important;
    height: 220px !important;
    overflow: hidden !important;
}
div[data-testid="stVideo"] video {
    max-height: 220px !important;
    height: 220px !important;
    width: 100% !important;
    object-fit: contain !important;
}
/* Also target by class in case testid changes */
.stVideo, .stVideo > div, .stVideo video {
    max-height: 220px !important;
    height: 220px !important;
    object-fit: contain !important;
}
</style>
""", unsafe_allow_html=True)
 
# ─────────────────────────────────────────────
# Row 1 — Dropdowns side by side (threat | camera)
# ─────────────────────────────────────────────
dd1, dd2, _spacer = st.columns([1, 2, 3])
 
with dd1:
    threat_sel = st.selectbox("🎯 Threat Type", ["Fire", "Violence", "Fall"],
                              key="vid_threat")
 
# ── Collect & naturally-sort mp4 files ──
vid_folder = os.path.join(VIDEOS_DIR, THREAT_VIDEO_FOLDER[threat_sel])
videos     = sorted(
    _glob.glob(os.path.join(vid_folder, "*.mp4")) if os.path.exists(vid_folder) else [],
    key=_natural_key
)
vid_names  = [os.path.splitext(os.path.basename(v))[0] for v in videos]
 
with dd2:
    if videos:
        vid_choice  = st.selectbox("📹 Camera Feed", vid_names, key="vid_choice")
        chosen_path = videos[vid_names.index(vid_choice)]
    else:
        st.info(f"No `.mp4` files in `{vid_folder}`")
        vid_choice  = None
        chosen_path = None

# ── Persist Step 7 selection into session state for Step 8 ──
st.session_state["selected_video"]        = vid_choice        # e.g. "fire_1"
st.session_state["selected_video_threat"] = threat_sel        # e.g. "Fire"
 
# ─────────────────────────────────────────────
# Row 2 — Full-width video | info cards
# ─────────────────────────────────────────────
vid_col, info_col = st.columns([5, 1])
 
with vid_col:
    if chosen_path:
        with open(chosen_path, "rb") as vf:
            video_bytes = vf.read()
        st.video(video_bytes, start_time=0)
    else:
        st.warning("No video selected.")
 
with info_col:
    # Try exact match first, then with .mp4, then threat-type-only as last resort
    _info_sub = pd.DataFrame()
    if vid_choice:
        for _vn in [vid_choice, vid_choice + ".mp4"]:
            _info_sub = query_db(f"""
                SELECT confidence_score AS confidence,
                       severity_level   AS severity,
                       timestamp
                FROM events
                WHERE LOWER(event_type) = LOWER('{threat_sel}')
                  AND video_name = '{_vn}'
                ORDER BY timestamp DESC
                LIMIT 1
            """)
            if not _info_sub.empty:
                break

    # Only fall back to threat-type-wide if absolutely no match found
    if _info_sub.empty:
        _info_sub = query_db(f"""
            SELECT confidence_score AS confidence,
                   severity_level   AS severity,
                   timestamp
            FROM events
            WHERE LOWER(event_type) = LOWER('{threat_sel}')
              AND video_name LIKE '%{vid_choice.split("_")[0] if vid_choice else ""}%'
            ORDER BY RANDOM()
            LIMIT 1
        """)

    conf      = float(_info_sub["confidence"].values[0]) if not _info_sub.empty else 0.87
    sev       = str(_info_sub["severity"].values[0]).strip().capitalize() if not _info_sub.empty else "Major"
    inc_time  = str(_info_sub["timestamp"].values[0])[:19] if not _info_sub.empty else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_color = "#e24b4a" if sev == "Critical" else "#ef9f27" if sev == "Major" else "#639922"

    st.markdown(f"""
    <div class="info-card"><div class="info-card-title">Threat Type</div>
    <div class="info-card-value">{threat_sel}</div></div>
    <div class="info-card"><div class="info-card-title">Confidence</div>
    <div class="info-card-value" style="color:#639922">{conf:.3f}</div></div>
    <div class="info-card"><div class="info-card-title">Severity</div>
    <div class="info-card-value" style="color:{sev_color}">{sev}</div></div>
    <div class="info-card"><div class="info-card-title">Status</div>
    <div class="info-card-value" style="color:#639922">● Monitoring Active</div></div>
    <div class="info-card"><div class="info-card-title">Timestamp</div>
    <div class="info-card-value">{inc_time}</div></div>
    """, unsafe_allow_html=True)
 
# ─────────────────────────────────────────────
# Row 3 — Full-width Evidence Frames
# ─────────────────────────────────────────────
if vid_choice:
    ev_subfolder    = _evidence_subfolder(vid_choice)   # fire_1→fire_1/ fight_1→fight_1/ fall_1→fall_1/
    evidence_folder = os.path.join(
        EVIDENCE_DIR,
        THREAT_EVIDENCE_FOLDER[threat_sel],
        ev_subfolder
    )
 
    frames = sorted(
        _glob.glob(os.path.join(evidence_folder, "*.jpg")) +
        _glob.glob(os.path.join(evidence_folder, "*.png")),
        key=_natural_key
    )
 
    if frames:
        st.markdown(
            f'<div style="margin-top:14px;margin-bottom:8px;font-size:14px;font-weight:700;">'
            f'🖼️ Evidence Frames — '
            f'<code style="background:#1e293b;padding:2px 8px;border-radius:4px;'
            f'color:#38bdf8;font-size:12px;">{vid_choice} · {sev}</code>'
            f'</div>',
            unsafe_allow_html=True,
        )
 
        # 3 frames per row — wider + taller frames
        COLS_PER_ROW = 3
        for i in range(0, len(frames), COLS_PER_ROW):
            batch = frames[i : i + COLS_PER_ROW]
            cols  = st.columns(COLS_PER_ROW)
            for col, frame_path in zip(cols, batch):
                with col:
                    frame_name = os.path.basename(frame_path)
                    ext  = frame_path.rsplit(".", 1)[-1].lower()
                    mime = "image/png" if ext == "png" else "image/jpeg"
                    with open(frame_path, "rb") as f:
                        img_b64 = base64.b64encode(f.read()).decode()
                    st.markdown(
                        f'<img src="data:{mime};base64,{img_b64}" '
                        f'style="width:100%;height:380px;object-fit:cover;'
                        f'border-radius:6px;margin-bottom:4px;" '
                        f'title="{frame_name}">',
                        unsafe_allow_html=True,
                    )
                    with st.expander(f"🔍 {frame_name}"):
                        st.image(frame_path, use_column_width=True)
    else:
        st.info(f"No evidence frames found in `{evidence_folder}`")

# ═══════════════════════════════════════════════════════
# 8. LOCATION & EMERGENCY ROUTING
# ═══════════════════════════════════════════════════════
st.markdown('<div class="section-header">📍 Location & Emergency Routing</div>',
            unsafe_allow_html=True)

# ── OSRM road distance + geometry ──
OSRM_BASE = "http://router.project-osrm.org"

@st.cache_data(show_spinner=False, ttl=3600)
def _osrm_route(lat1, lon1, lat2, lon2):
    """
    Calls the public OSRM demo server.
    Returns (distance_km, duration_min, [[lat,lon], ...] geometry).
    Falls back to haversine + straight line on any error.
    """
    try:
        url = (
            f"{OSRM_BASE}/route/v1/driving/"
            f"{lon1},{lat1};{lon2},{lat2}"
            f"?overview=full&geometries=geojson&steps=false"
        )
        resp = _requests.get(url, timeout=5)
        if resp.status_code == 200:
            data  = resp.json()
            route = data["routes"][0]
            dist_km  = round(route["distance"] / 1000, 2)
            dur_min  = round(route["duration"] / 60, 1)
            coords   = route["geometry"]["coordinates"]   # [[lon,lat], ...]
            # GeoJSON is [lon,lat] — flip to [lat,lon] for folium
            geom = [[c[1], c[0]] for c in coords]
            return dist_km, dur_min, geom
    except Exception:
        pass
    # ── Haversine fallback ──
    R    = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a    = (math.sin(dlat / 2) ** 2 +
            math.cos(math.radians(lat1)) *
            math.cos(math.radians(lat2)) *
            math.sin(dlon / 2) ** 2)
    dist_km = round(R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)), 2)
    return dist_km, None, [[lat1, lon1], [lat2, lon2]]

@st.cache_data(show_spinner=False, ttl=3600)
def _road_distance(lat1, lon1, lat2, lon2):
    """Convenience wrapper — returns only km (for sorting)."""
    dist_km, _, _ = _osrm_route(lat1, lon1, lat2, lon2)
    return dist_km

def _fcol(edf, *candidates):
    for c in candidates:
        if c in edf.columns:
            return c
    return None

@st.cache_data(show_spinner=False, ttl=300)
def _load_em(table):
    edf = query_db(f"SELECT * FROM {table}")
    if edf.empty:
        kind = {"police_stations": "police", "fire_stations": "fire", "hospitals": "hospital"}.get(table, "police")
        edf = demo_emergency(kind)
    edf.columns = [c.lower() for c in edf.columns]
    return edf

# ── Severity-based alert logic ──
# Fall:     minor/major → family only | critical → family + hospital
# Fire:     minor → none | major/critical → fire_station + hospital
# Violence: minor/major → none | critical → hospital + police
def _who_to_alert(threat, severity):
    t = threat.lower()
    s = severity.lower()
    if t == "fall":
        if s in ("minor", "major"):
            return ["family"]
        elif s == "critical":
            return ["family", "hospital"]
    elif t == "fire":
        if s == "minor":
            return []
        elif s in ("major", "critical"):
            return ["fire_station", "hospital"]
    elif t == "violence":
        if s in ("minor", "major"):
            return []
        elif s == "critical":
            return ["hospital", "police"]
    return []

# ── Two distinct route colours for dual connections ──
_ROUTE_COLORS = {
    "hospital":     "#185fa5",   # blue
    "fire_station": "#e05c00",   # deep orange
    "police":       "#7c3aed",   # purple
    "family":       "#639922",   # green
}

_EM_PIN = {
    "hospital":     {"folium": "blue",   "hex": "#185fa5", "label": "🏥 Hospital"},
    "fire_station": {"folium": "orange", "hex": "#e05c00", "label": "🚒 Fire Station"},
    "police":       {"folium": "purple", "hex": "#7c3aed", "label": "🚔 Police Station"},
}
_INC_HEX   = "#e24b4a"
_sev_color = {"Critical": "#e24b4a", "Major": "#ef9f27", "Minor": "#639922"}

# ── Pick incident from Step 7 selection ──
_vid7    = st.session_state.get("selected_video")
_threat7 = st.session_state.get("selected_video_threat")
_row     = None

if _vid7:
    for _vname in [_vid7, _vid7 + ".mp4"]:
        _tmp = query_db(f"""
            SELECT incident_id, video_name AS camera_id,
                   event_type AS threat_type, severity_level AS severity,
                   confidence_score AS confidence,
                   timestamp, location, latitude, longitude
            FROM events WHERE video_name = '{_vname}'
            ORDER BY timestamp DESC LIMIT 1
        """)
        if not _tmp.empty:
            _row = _tmp.iloc[0].to_dict()
            break

if _row is None and _threat7:
    _tmp = query_db(f"""
        SELECT incident_id, video_name AS camera_id,
               event_type AS threat_type, severity_level AS severity,
               confidence_score AS confidence,
               timestamp, location, latitude, longitude
        FROM events WHERE LOWER(event_type) = LOWER('{_threat7}')
        ORDER BY timestamp DESC LIMIT 1
    """)
    if not _tmp.empty:
        _row = _tmp.iloc[0].to_dict()

if _row is None:
    _tmp = query_db("""
        SELECT incident_id, video_name AS camera_id,
               event_type AS threat_type, severity_level AS severity,
               confidence_score AS confidence,
               timestamp, location, latitude, longitude
        FROM events ORDER BY timestamp DESC LIMIT 1
    """)
    if not _tmp.empty:
        _row = _tmp.iloc[0].to_dict()

if _row is None:
    _dr = demo_incidents(n=5).iloc[0]
    _row = {
        "incident_id": int(_dr.get("incident_id", 1)),
        "camera_id":   _vid7 or str(_dr.get("camera_id", "demo")),
        "threat_type": _threat7 or str(_dr.get("threat_type", "Fall")),
        "severity":    str(_dr.get("severity", "Major")),
        "confidence":  float(_dr.get("confidence", 0.87)),
        "timestamp":   str(_dr.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))),
        "location":    str(_dr.get("location", "Bengaluru")),
        "latitude":    float(_dr.get("latitude", 12.9716)),
        "longitude":   float(_dr.get("longitude", 77.5946)),
    }

inc_threat   = str(_row.get("threat_type",  _threat7 or "Fall")).strip().capitalize()
inc_severity = str(_row.get("severity",     "Major")).strip().capitalize()
inc_lat      = float(_row.get("latitude",   12.9716))
inc_lon      = float(_row.get("longitude",  77.5946))
inc_loc      = str(_row.get("location",     "—"))
inc_ts       = str(_row.get("timestamp",    "—"))
inc_cam      = str(_row.get("camera_id",    _vid7 or "—"))
inc_conf     = float(_row.get("confidence", 0))
svc          = _sev_color.get(inc_severity, "#888")
alert_targets = _who_to_alert(inc_threat, inc_severity)

# ── Load nearest services: 2 hospitals, 1 fire station, 1 police station ──
_police_df = _load_em("police_stations")
_fire_df   = _load_em("fire_stations")
_hosp_df   = _load_em("hospitals")

# Load family contacts from DB — correct columns: person_name, relation, phone_number, email, home_location
def _load_family_contacts(origin_lat=None, origin_lon=None):
    fc = query_db("""
        SELECT contact_id, person_name, relation, phone_number, email, home_location,
               latitude, longitude
        FROM family_contacts
        ORDER BY contact_id
    """)
    if fc.empty:
        return fc
    fc.columns = [c.lower() for c in fc.columns]
    # If we have incident coords and family has lat/lon, pick nearest 1 person
    if origin_lat is not None and origin_lon is not None:
        lc = next((c for c in ["latitude", "lat"] if c in fc.columns), None)
        oc = next((c for c in ["longitude", "lon", "lng"] if c in fc.columns), None)
        if lc and oc:
            try:
                fc["_dist_km"] = fc.apply(
                    lambda r: _haversine_km(origin_lat, origin_lon,
                                            float(r[lc]), float(r[oc])),
                    axis=1,
                )
                fc = fc.sort_values("_dist_km").head(1).reset_index(drop=True)
            except Exception:
                fc = fc.head(1)
        else:
            fc = fc.head(1)
    else:
        fc = fc.head(1)
    return fc

def _nearest_n(edf, origin_lat, origin_lon, n=2):
    """Find n nearest rows in edf to (origin_lat, origin_lon) using OSRM road distance."""
    if edf.empty:
        return edf
    lc = _fcol(edf, "latitude", "lat")
    oc = _fcol(edf, "longitude", "lon", "lng")
    if not lc or not oc:
        return edf.head(n)
    edf = edf.copy()
    # Use OSRM for real road distance AND duration
    dist_results = edf.apply(
        lambda r: _osrm_route(origin_lat, origin_lon, float(r[lc]), float(r[oc])),
        axis=1
    )
    edf["_dist_km"] = dist_results.apply(lambda x: x[0])
    edf["_dur_min"] = dist_results.apply(lambda x: x[1])
    return edf.sort_values("_dist_km").head(n)

_h2 = _nearest_n(_hosp_df,   inc_lat, inc_lon, n=2)   # 2 nearest hospitals (show both markers)
_h1 = _nearest_n(_hosp_df,   inc_lat, inc_lon, n=1)   # single nearest hospital (route only to this)
_f1 = _nearest_n(_fire_df,   inc_lat, inc_lon, n=1)   # 1 nearest fire station
_p1 = _nearest_n(_police_df, inc_lat, inc_lon, n=1)   # 1 nearest police station

# ── Layout ──
_side, _map_col = st.columns([1, 3])

with _side:
    # ── Incident Details card ──
    st.markdown(f"""
<div style="background:#fff;border:1px solid #e0e0e0;border-radius:10px;
            padding:8px 12px;margin-bottom:10px;">
    <div style="font-size:12px;font-weight:800;color:#1a1a2e;margin-bottom:5px;
                border-bottom:1px solid #f0f0f0;padding-bottom:4px;">
        📌 Incident Details
    </div>
    <table style="width:100%;font-size:12px;line-height:1.65;border-collapse:collapse;">
        <tr>
            <td style="color:#999;width:36%;vertical-align:top;padding-right:5px;padding-bottom:2px;">📍 Location</td>
            <td style="color:#1a1a2e;font-weight:600;">{inc_loc}</td>
        </tr>
        <tr>
            <td style="color:#999;vertical-align:top;padding-bottom:2px;">⚠️ Severity</td>
            <td style="color:{svc};font-weight:700;">{inc_severity}</td>
        </tr>
        <tr>
            <td style="color:#999;vertical-align:top;padding-bottom:2px;">🕐 Time</td>
            <td style="color:#1a1a2e;font-weight:600;">{inc_ts}</td>
        </tr>
        <tr>
            <td style="color:#999;vertical-align:top;padding-bottom:2px;">🎯 Threat</td>
            <td style="color:#1a1a2e;font-weight:600;">{inc_threat}</td>
        </tr>
        <tr>
            <td style="color:#999;vertical-align:top;">📹 Video</td>
            <td style="color:#1a1a2e;font-weight:600;">{inc_cam}</td>
        </tr>
    </table>
</div>""", unsafe_allow_html=True)

    # ── Show alert condition ──
    if not alert_targets:
        st.markdown(f"""
<div style="background:#f9f9f9;border:1px solid #ddd;border-radius:8px;
            padding:8px 12px;margin-bottom:8px;font-size:11px;color:#666;">
    ℹ️ <b>{inc_threat} — {inc_severity}</b>: No emergency alert required.
</div>""", unsafe_allow_html=True)
    else:
        tgt_str = ", ".join(t.replace("_", " ").title() for t in alert_targets)
        st.markdown(f"""
<div style="background:#eaf0fb;border:1px solid #185fa5;border-radius:8px;
            padding:8px 12px;margin-bottom:8px;font-size:11px;color:#0d2e5c;">
    🚨 <b>Alerting:</b> {tgt_str}
</div>""", unsafe_allow_html=True)

    def _sidebar_card(edf, title, hex_color, icon):
        if edf.empty:
            return
        lc  = _fcol(edf, "latitude",  "lat")
        oc  = _fcol(edf, "longitude", "lon", "lng")
        nc  = _fcol(edf, "name", "station_name", "hospital_name", "facility_name")
        ac  = _fcol(edf, "address",   "location", "addr")
        pc  = _fcol(edf, "phone",     "phone_number", "contact", "contact_number")
        emc = _fcol(edf, "email",     "email_address")
        # ── Heading in distinct colour ──
        st.markdown(
            f'<div style="font-size:12px;font-weight:800;color:{hex_color};'
            f'margin:10px 0 6px 0;border-left:3px solid {hex_color};padding-left:6px;">'
            f'{icon} Nearest {title}</div>',
            unsafe_allow_html=True,
        )
        for i, (_, r) in enumerate(edf.iterrows()):
            dist_km = r.get("_dist_km", None)
            dur_min = r.get("_dur_min", None)
            ds   = f"{dist_km:.2f} km"    if dist_km is not None else "—"
            durs = f"~{int(round(dur_min))} min drive" if dur_min is not None else ""
            name  = r[nc]  if nc  else "—"
            addr  = r[ac]  if ac  else "—"
            phone = r[pc]  if pc  else "—"
            email = r[emc] if emc else "—"
            st.markdown(f"""
<div style="background:#fff;border:1px solid {hex_color}44;
            border-radius:8px;padding:8px 10px;margin-bottom:7px;">
    <div style="font-size:11px;font-weight:700;color:{hex_color};margin-bottom:3px;">{icon} {name}</div>
    <div style="font-size:10px;color:#555;line-height:1.8;">
        <b style="color:#888;">🛣️ Distance:</b>
        <b style="color:{hex_color};">{ds}</b>
        {"&nbsp;·&nbsp;<span style='color:#555;'>" + durs + "</span>" if durs else ""}<br>
        <b style="color:#888;">📍</b> {addr}<br>
        <b style="color:#888;">📞</b> {phone}<br>
        <b style="color:#888;">📧</b> {email}
    </div>
</div>""", unsafe_allow_html=True)

    if "hospital"     in alert_targets: _sidebar_card(_h1, "Hospital (Nearest)",  "#185fa5", "🏥")
    if "fire_station" in alert_targets: _sidebar_card(_f1, "Fire Station",         "#e05c00", "🚒")
    if "police"       in alert_targets: _sidebar_card(_p1, "Police Station",       "#7c3aed", "🚔")

    # ── Family contacts from DB — nearest 1 person to incident ──
    if "family" in alert_targets:
        fam_df = _load_family_contacts(origin_lat=inc_lat, origin_lon=inc_lon)
        st.markdown(
            '<div style="font-size:12px;font-weight:800;color:#639922;'
            'margin:10px 0 6px 0;border-left:3px solid #639922;padding-left:6px;">'
            '👨‍👩‍👧 Family Contacts</div>',
            unsafe_allow_html=True,
        )
        if fam_df.empty:
            st.markdown("""
<div style="background:#eaf3de;border:1px solid #639922;border-radius:8px;
            padding:8px 10px;margin-bottom:7px;font-size:11px;color:#27500a;">
    Alert dispatched to registered family contacts.
</div>""", unsafe_allow_html=True)
        else:
            for _, fr in fam_df.iterrows():
                # Support both old column names and real DB column names
                fname    = fr.get("person_name",   fr.get("name",     "—"))
                relation = fr.get("relation",       "—")
                fphone   = fr.get("phone_number",   fr.get("phone",   "—"))
                femail   = fr.get("email",          "—")
                floc     = fr.get("home_location",  fr.get("address", "—"))
                st.markdown(f"""
<div style="background:#eaf3de;border:1px solid #639922;
            border-radius:8px;padding:8px 10px;margin-bottom:7px;">
    <div style="font-size:12px;font-weight:700;color:#27500a;margin-bottom:3px;">👤 {fname}</div>
    <div style="font-size:10px;color:#3a5c1a;line-height:1.8;">
        <b>Relation:</b> {relation}<br>
        <b>📞</b> {fphone}<br>
        <b>📧</b> {femail}<br>
        <b>📍</b> {floc}
    </div>
</div>""", unsafe_allow_html=True)

with _map_col:
    _inc_map = folium.Map(location=[inc_lat, inc_lon], zoom_start=14, tiles="OpenStreetMap")

    _inc_tip = f"""<div style="font-family:Arial;min-width:230px;padding:10px;">
    <div style="font-size:14px;font-weight:900;color:{_INC_HEX};">⚠️ Incident Location</div>
    <hr style="margin:5px 0;border-color:#eee;">
    <div style="font-size:12px;line-height:2.0;">
        <b>Location:</b> {inc_loc}<br>
        <b>Severity:</b> <span style="color:{svc};font-weight:700;">{inc_severity}</span><br>
        <b>Time:</b> {inc_ts}<br>
        <b>Lat:</b> {inc_lat} &nbsp;&nbsp; <b>Lon:</b> {inc_lon}
    </div>
</div>"""
    folium.Marker(
        location=[inc_lat, inc_lon],
        tooltip=folium.Tooltip(_inc_tip, sticky=True),
        popup=folium.Popup(_inc_tip, max_width=280),
        icon=folium.Icon(color="red", icon_color="white", icon="exclamation-triangle", prefix="fa"),
    ).add_to(_inc_map)

    # ── Draw real OSRM road geometry on the map ──
    def _osrm_polyline(lat1, lon1, lat2, lon2, color, weight=4, opacity=0.85):
        """
        Fetches the actual road geometry from OSRM and draws it.
        Falls back to a straight PolyLine if the API is unreachable.
        """
        _, _, geom = _osrm_route(lat1, lon1, lat2, lon2)
        folium.PolyLine(
            locations=geom,
            color=color,
            weight=weight,
            opacity=opacity,
            line_cap="round",
            line_join="round",
        ).add_to(_inc_map)
        # Direction arrow at approx midpoint of the geometry
        if len(geom) >= 2:
            mid_idx = len(geom) // 2
            arrow_pt = geom[mid_idx]
            folium.Marker(
                location=arrow_pt,
                icon=folium.DivIcon(
                    html=f'<div style="color:{color};font-size:15px;font-weight:900;'
                         f'text-shadow:0 0 4px white;opacity:0.9;">➤</div>',
                    icon_size=(20, 20), icon_anchor=(10, 10)
                )
            ).add_to(_inc_map)

    def _map_em(edf, em_type, route_to_nearest_only=False):
        """
        Plots markers for all rows in edf.
        If route_to_nearest_only=True, draws the road route ONLY to the first row
        (assumed to be the nearest, since edf is already sorted by distance).
        """
        if edf.empty:
            return
        cfg       = _EM_PIN[em_type]
        route_col = _ROUTE_COLORS[em_type]
        lc  = _fcol(edf, "latitude",  "lat")
        oc  = _fcol(edf, "longitude", "lon", "lng")
        nc  = _fcol(edf, "name", "station_name", "hospital_name", "facility_name")
        ac  = _fcol(edf, "address",   "location", "addr")
        pc  = _fcol(edf, "phone",     "phone_number", "contact", "contact_number")
        emc = _fcol(edf, "email",     "email_address")
        if not lc or not oc:
            return
        for idx, (_, r) in enumerate(edf.iterrows()):
            lv       = float(r[lc])
            ov       = float(r[oc])
            dist_km  = r.get("_dist_km",  None)
            dur_min  = r.get("_dur_min",  None)
            dist_str = f"{dist_km:.2f} km"           if dist_km is not None else "—"
            dur_str  = f"~{int(round(dur_min))} min" if dur_min is not None else "—"
            is_nearest = (idx == 0)
            rank_badge = "🥇 Nearest" if is_nearest else "🥈 2nd Nearest"
            tip = f"""<div style="font-family:Arial;min-width:240px;padding:10px 14px;">
    <div style="font-size:13px;font-weight:900;color:{cfg['hex']};">{cfg['label']} &nbsp;<span style="font-size:11px;color:#888;">{rank_badge}</span></div>
    <hr style="margin:4px 0;border-color:#eee;">
    <div style="font-size:11px;line-height:2.0;">
        <b>Name:</b> {r[nc] if nc else '—'}<br>
        <b>Address:</b> {r[ac] if ac else '—'}<br>
        <b>Phone:</b> {r[pc] if pc else '—'}<br>
        <b>Email:</b> {r[emc] if emc else '—'}<br>
        <b>🛣️ Road Distance:</b>
        <span style="color:{cfg['hex']};font-weight:700;">{dist_str}</span><br>
        <b>🚗 Est. Drive Time:</b>
        <span style="color:{cfg['hex']};font-weight:700;">{dur_str}</span>
        {"<br><b style='color:#16a34a;'>✅ Route drawn to this location</b>" if is_nearest else "<br><span style='color:#aaa;font-size:10px;'>ℹ️ No route drawn (not nearest)</span>"}
    </div>
</div>"""
            # Nearest marker: solid icon; 2nd: slightly faded DivIcon
            if is_nearest:
                pin_icon = folium.Icon(color=cfg["folium"], icon_color="white",
                                       icon="map-marker", prefix="fa")
            else:
                pin_icon = folium.Icon(color="gray", icon_color="white",
                                       icon="map-marker", prefix="fa")
            folium.Marker(
                location=[lv, ov],
                tooltip=folium.Tooltip(tip, sticky=True),
                popup=folium.Popup(tip, max_width=300),
                icon=pin_icon,
            ).add_to(_inc_map)
            # Draw route ONLY to the nearest (idx==0), or always if not restricting
            if not route_to_nearest_only or is_nearest:
                _osrm_polyline(inc_lat, inc_lon, lv, ov, color=route_col, weight=5)

    # Hospital: show 2 markers, route only to nearest (blue line)
    # Fire/Police: show 1 marker, route to it (orange/purple line)
    # Two distinct route colours: blue for hospital, orange/purple for other service
    if "hospital"     in alert_targets: _map_em(_h2, "hospital",     route_to_nearest_only=True)
    if "fire_station" in alert_targets: _map_em(_f1, "fire_station",  route_to_nearest_only=False)
    if "police"       in alert_targets: _map_em(_p1, "police",        route_to_nearest_only=False)

    # ── Legend: 2 distinct route colours ──
    _legend_items = [(_INC_HEX, "⚠️ Incident")]
    if "hospital"     in alert_targets:
        _legend_items.append((_ROUTE_COLORS["hospital"],     "🏥 Hospital route (nearest only)"))
    if "fire_station" in alert_targets:
        _legend_items.append((_ROUTE_COLORS["fire_station"], "🚒 Fire Station route"))
    if "police"       in alert_targets:
        _legend_items.append((_ROUTE_COLORS["police"],       "🚔 Police route"))

    _legend_rows = "".join(
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">'
        f'<span style="width:24px;height:5px;background:{hx};border-radius:3px;'
        f'display:inline-block;"></span>'
        f'<span style="color:#222;font-size:12px;">{lbl}</span></div>'
        for hx, lbl in _legend_items
    )

    _no_alert_note = ""
    if not alert_targets:
        _no_alert_note = (
            f'<div style="margin-top:8px;border-top:1px solid #eee;padding-top:6px;'
            f'font-size:11px;color:#888;">ℹ️ {inc_threat} {inc_severity}: No alert needed</div>'
        )

    _inc_map.get_root().html.add_child(folium.Element(f"""
<div style="position:fixed;bottom:30px;right:12px;z-index:9999;
            background:white;padding:10px 14px;border-radius:10px;
            border:1px solid #ddd;font-family:Arial;
            box-shadow:0 2px 10px rgba(0,0,0,0.15);">
    <div style="font-weight:800;font-size:11px;color:#333;
                margin-bottom:7px;text-transform:uppercase;letter-spacing:.05em;">ROUTE LEGEND</div>
    {_legend_rows}
    {_no_alert_note}
</div>"""))

    st_folium(_inc_map, use_container_width=True, height=580, returned_objects=[])

# ═══════════════════════════════════════════════════════
# 9. ALERT & COMMUNICATION
# ═══════════════════════════════════════════════════════
st.markdown('<div class="section-header">🔔 Alert & Communication</div>', unsafe_allow_html=True)

# ── Dark theme CSS for Section 9 ──
st.markdown("""
<style>
.alert-section-wrap { background:#1a1a2e; border-radius:12px; padding:20px 24px; }
.alert-sec-label {
    font-size:14px; font-weight:700; color:#f0f0f0;
    margin-bottom:12px;
}
</style>
""", unsafe_allow_html=True)

# ── Resolve selected video's incident_id from events DB ──
_alert_vid    = st.session_state.get("selected_video")
_alert_threat = st.session_state.get("selected_video_threat")

_alert_incident_id = None
_alert_event_type  = _alert_threat or "Fire"
_alert_severity    = "Major"

if _alert_vid:
    for _vn in [_alert_vid, _alert_vid + ".mp4"]:
        _tmp_ev = query_db(f"""
            SELECT incident_id, event_type, severity_level
            FROM events
            WHERE video_name = '{_vn}'
            ORDER BY timestamp DESC LIMIT 1
        """)
        if not _tmp_ev.empty:
            _alert_incident_id = int(_tmp_ev.iloc[0]["incident_id"])
            _alert_event_type  = str(_tmp_ev.iloc[0]["event_type"]).strip().capitalize()
            _alert_severity    = str(_tmp_ev.iloc[0]["severity_level"]).strip().capitalize()
            break

if _alert_incident_id is None and _alert_threat:
    _tmp_ev = query_db(f"""
        SELECT incident_id, event_type, severity_level
        FROM events
        WHERE LOWER(event_type) = LOWER('{_alert_threat}')
        ORDER BY timestamp DESC LIMIT 1
    """)
    if not _tmp_ev.empty:
        _alert_incident_id = int(_tmp_ev.iloc[0]["incident_id"])
        _alert_event_type  = str(_tmp_ev.iloc[0]["event_type"]).strip().capitalize()
        _alert_severity    = str(_tmp_ev.iloc[0]["severity_level"]).strip().capitalize()

# ── Use variables from Section 8 ──
def _get_nearest_name(edf):
    nc = _fcol(edf, "name", "station_name", "hospital_name", "facility_name")
    if nc is not None and not edf.empty:
        return str(edf.iloc[0][nc])
    return "—"

_hosp_name   = _get_nearest_name(_h1) if "hospital"     in alert_targets else "—"
_fire_name   = _get_nearest_name(_f1) if "fire_station" in alert_targets else "—"
_police_name = _get_nearest_name(_p1) if "police"       in alert_targets else "—"

# ── Fetch alerts from DB ──
def _get_incident_alerts(incident_id):
    if incident_id is None:
        return pd.DataFrame()
    df_a = query_db(f"""
        SELECT alert_id, incident_id, event_type, severity_level,
               sent_to, receiver_type, contact_number, alert_message,
               status, timestamp, alert_mode
        FROM alerts
        WHERE incident_id = {incident_id}
        ORDER BY timestamp ASC
    """)
    if not df_a.empty:
        df_a.columns = [c.lower() for c in df_a.columns]
    return df_a

# ── Build alert log ──
def _build_alert_log(incident_id, event_type, severity):
    now_str = datetime.now().strftime("%H:%M:%S")
    df_a = _get_incident_alerts(incident_id)
    rows = []

    if not df_a.empty:
        for _, r in df_a.iterrows():
            mode    = str(r.get("alert_mode", r.get("status", "SMS"))).strip().upper()
            recv    = str(r.get("sent_to",       "—"))
            rtype   = str(r.get("receiver_type", "")).lower()
            contact = str(r.get("contact_number","—"))
            msg     = str(r.get("alert_message", "—"))
            sev     = str(r.get("severity_level", severity)).strip().capitalize()
            ts      = str(r.get("timestamp",     now_str))[-8:]
            status  = str(r.get("status",        "sent")).lower()

            if   "hospital" in rtype: recv_icon = "🏥"
            elif "police"   in rtype: recv_icon = "🚔"
            elif "fire"     in rtype: recv_icon = "🚒"
            elif "family"   in rtype: recv_icon = "👨‍👩‍👧"
            else:                     recv_icon = "📋"

            if   "sms"   in mode.lower(): log_mode = "SMS sent"
            elif "email" in mode.lower(): log_mode = "Email sent"
            elif "call"  in mode.lower(): log_mode = "Call initiated"
            else:                         log_mode = "SMS sent"

            rows.append({
                "mode": log_mode, "receiver_icon": recv_icon,
                "receiver_name": recv,
                "detail": f"{contact} · {msg[:40]}" if msg != "—" else contact,
                "severity": sev, "timestamp": ts, "status": status,
            })
        return rows

    # ── Synthesise from alert_targets ──
    alert_map = []
    for tgt in alert_targets:
        if tgt == "hospital":
            alert_map.append(("🏥", _hosp_name,      "Ambulance dispatched"))
        elif tgt == "fire_station":
            alert_map.append(("🚒", _fire_name,       "Fire crew dispatched"))
        elif tgt == "police":
            alert_map.append(("🚔", _police_name,     "Incident reported"))
        elif tgt == "family":
            alert_map.append(("👨‍👩‍👧", "Family Contact", "Safety alert sent"))

    for icon, name, msg in alert_map:
        for log_mode in ["SMS sent", "Email sent", "Call initiated"]:
            rows.append({
                "mode": log_mode, "receiver_icon": icon,
                "receiver_name": name, "detail": msg,
                "severity": severity, "timestamp": now_str, "status": "sent",
            })
    return rows

_alert_log = _build_alert_log(_alert_incident_id, _alert_event_type, _alert_severity)

# ── Layout ──
_al_col, _at_col = st.columns([2, 1])

with _al_col:
    st.markdown(
        '<div style="font-size:14px;font-weight:700;color:#f0f0f0;'
        'margin-bottom:12px;">📋 Alert Log</div>',
        unsafe_allow_html=True,
    )

    if not _alert_log:
        st.markdown(
            '<div style="background:#16213e;border:1px solid #333;border-radius:8px;'
            'padding:12px 14px;font-size:13px;color:#aaa;">'
            'ℹ️ No alerts triggered for this incident / severity level.</div>',
            unsafe_allow_html=True,
        )
    else:
        for row in _alert_log:
            mode   = row["mode"]
            icon   = row["receiver_icon"]
            name   = row["receiver_name"]
            detail = row["detail"]
            ts     = row["timestamp"]

            if "SMS" in mode or "Email" in mode:
                card_bg  = "#1a2e1a"
                card_bd  = "#639922"
                mode_col = "#9fe060"   # ← bright green for dark bg
                mode_ico = "✅"
            else:  # Call
                card_bg  = "#16213e"
                card_bd  = "#185fa5"
                mode_col = "#60a5fa"   # ← bright blue for dark bg
                mode_ico = "📞"

            st.markdown(f"""
<div style="background:{card_bg};border-left:4px solid {card_bd};
            border-radius:0 8px 8px 0;padding:10px 16px;
            margin-bottom:8px;font-size:13px;">
    <b style="color:{mode_col};">{mode_ico} {mode}</b>
    &nbsp;·&nbsp;
    <span style="color:#e0e0e0;">{icon} <b style="color:#fff;">{name}</b></span>
    &nbsp;·&nbsp;
    <span style="color:#ccc;">{detail}</span>
    &nbsp;·&nbsp;
    <span style="color:#888;">{ts}</span>
</div>""", unsafe_allow_html=True)

with _at_col:
    st.markdown(
        '<div style="font-size:14px;font-weight:700;color:#f0f0f0;'
        'margin-bottom:12px;">🚨 Manual Alert Trigger</div>',
        unsafe_allow_html=True,
    )

    _all_ids     = query_db("SELECT DISTINCT incident_id FROM events ORDER BY incident_id")
    _id_list     = list(_all_ids["incident_id"].astype(int)) if not _all_ids.empty else [1]
    _default_idx = _id_list.index(_alert_incident_id) if _alert_incident_id in _id_list else 0

    _manual_id  = st.selectbox("Incident ID",  _id_list, index=_default_idx, key="manual_alert_id")
    _alert_type = st.selectbox("Alert type",   ["SMS", "Email", "Call"],      key="manual_alert_type")

    if st.button("🚨 Send Alert", use_container_width=True, key="manual_send_btn"):
        _m_ev = query_db(f"""
            SELECT event_type, severity_level, location, timestamp
            FROM events WHERE incident_id = {_manual_id} LIMIT 1
        """)
        if not _m_ev.empty:
            _m_threat = str(_m_ev.iloc[0]["event_type"]).capitalize()
            _m_sev    = str(_m_ev.iloc[0]["severity_level"]).capitalize()
            _m_loc    = str(_m_ev.iloc[0]["location"])
            _m_ts     = str(_m_ev.iloc[0]["timestamp"])
        else:
            _m_threat, _m_sev, _m_loc, _m_ts = "Unknown", "Major", "—", "—"

        _sev_col = {"Critical":"#e24b4a","Major":"#ef9f27","Minor":"#639922"}.get(_m_sev,"#888")

        st.markdown(f"""
<div style="background:#16213e;border:1px solid #639922;border-radius:8px;
            padding:10px 14px;margin-top:8px;font-size:12px;">
    <span style="color:#9fe060;">✅ <b>{_alert_type} alert dispatched</b></span><br>
    <span style="color:#ccc;">Incident <b style="color:#fff;">#{_manual_id}</b>
    · {_m_threat}
    · <span style="color:{_sev_col};font-weight:700;">{_m_sev}</span></span><br>
    <span style="color:#aaa;">📍 {_m_loc}</span><br>
    <span style="color:#888;">🕐 {_m_ts}</span>
</div>""", unsafe_allow_html=True)
        
# ═══════════════════════════════════════════════════════
# 10. INCIDENT LOGS
# ═══════════════════════════════════════════════════════
st.markdown('<div class="section-header">📋 Incident Logs</div>', unsafe_allow_html=True)

# ── Labels CSS only (no table CSS override — it breaks rendering) ──
st.markdown("""
<style>
.inc-log-label {
    font-size: 11px; color: #aaa;
    text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px;
}
.inc-log-count { font-size: 13px; color: #ccc; margin-bottom: 14px; }
</style>
""", unsafe_allow_html=True)

# ── Load full incident log from DB ──
_log_df = query_db("""
    SELECT
        incident_id,
        video_name,
        timestamp,
        location,
        severity_level,
        confidence_score,
        latitude,
        longitude
    FROM events
    ORDER BY timestamp DESC
""")

if _log_df.empty:
    _log_df = df[["incident_id", "camera_id", "timestamp", "location",
                  "severity", "confidence", "latitude", "longitude"]].copy()
    _log_df.columns = ["incident_id", "video_name", "timestamp", "location",
                       "severity_level", "confidence_score", "latitude", "longitude"]

_log_df.columns = [c.lower() for c in _log_df.columns]

# ── Normalize severity ──
if "severity_level" in _log_df.columns:
    _log_df["severity_level"] = _log_df["severity_level"].str.strip().str.capitalize()

# ── Filters row ──
_lf1, _lf2, _lf3 = st.columns([1.5, 2, 1.5])

with _lf1:
    st.markdown('<div class="inc-log-label">Severity</div>', unsafe_allow_html=True)
    _sev_filter = st.multiselect(
        "sev", ["Critical", "Major", "Minor"],
        default=["Critical", "Major", "Minor"],
        key="log_sev_filter",
        label_visibility="collapsed",
    )

with _lf2:
    st.markdown('<div class="inc-log-label">Search Location</div>', unsafe_allow_html=True)
    _loc_search = st.text_input(
        "loc", placeholder="e.g. Silk Board",
        key="log_loc_search",
        label_visibility="collapsed",
    )

with _lf3:
    st.markdown('<div class="inc-log-label">Sort By</div>', unsafe_allow_html=True)
    _sort_col = st.selectbox(
        "sort", ["timestamp", "incident_id", "severity_level", "confidence_score"],
        key="log_sort_col",
        label_visibility="collapsed",
    )

# ── Apply filters ──
_filtered_log = _log_df.copy()

if _sev_filter:
    _filtered_log = _filtered_log[_filtered_log["severity_level"].isin(_sev_filter)]

if _loc_search.strip():
    _filtered_log = _filtered_log[
        _filtered_log["location"].str.contains(_loc_search.strip(), case=False, na=False)
    ]

if _sort_col in _filtered_log.columns:
    _filtered_log = _filtered_log.sort_values(_sort_col, ascending=False)

# ── Count label ──
st.markdown(
    f'<div class="inc-log-count">Showing <b style="color:#fff;">{len(_filtered_log)}</b>'
    f' of <b style="color:#fff;">{len(_log_df)}</b> incidents</div>',
    unsafe_allow_html=True,
)

# ── Display columns ──
_show_cols = [c for c in [
    "incident_id", "video_name", "timestamp", "location",
    "severity_level", "confidence_score", "latitude", "longitude"
] if c in _filtered_log.columns]

_display_df = _filtered_log[_show_cols].reset_index(drop=True)

# ── Severity colour using pandas Styler (.map is modern, .applymap deprecated) ──
def _sev_badge(val):
    colors = {"Critical": "#e24b4a", "Major": "#ef9f27", "Minor": "#639922"}
    c = colors.get(str(val).strip().capitalize(), "#888")
    return f"color: {c}; font-weight: 700;"

if "severity_level" in _display_df.columns:
    try:
        _styled = _display_df.style.map(_sev_badge, subset=["severity_level"])
    except AttributeError:
        # pandas < 2.1 fallback
        _styled = _display_df.style.applymap(_sev_badge, subset=["severity_level"])
    st.dataframe(_styled, use_container_width=True, hide_index=True, height=420)
else:
    st.dataframe(_display_df, use_container_width=True, hide_index=True, height=420)

# ── Download CSV button ──
_csv_data = _filtered_log[_show_cols].to_csv(index=False).encode("utf-8")
st.download_button(
    label="⬇️ Download CSV",
    data=_csv_data,
    file_name=f"incident_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
    mime="text/csv",
    key="log_download_btn",
)

# ═══════════════════════════════════════════════════════
# FOOTER
# ═══════════════════════════════════════════════════════
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("""
<hr style="border:none;border-top:1px solid #e8e8e8;margin:0 0 10px 0">
<p style="text-align:center;color:#aaa;font-size:12px">
    SmartSurveillance AI &nbsp;·&nbsp; Multi-Threat Detection System &nbsp;·&nbsp; Bengaluru
    &nbsp;·&nbsp; OpenCV &nbsp;·&nbsp; YOLOv8 &nbsp;·&nbsp; Plotly &nbsp;·&nbsp; Folium &nbsp;·&nbsp; SQLite
</p>
""", unsafe_allow_html=True)
