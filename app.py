import os
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from PIL import Image
import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
from features import extract_features, FEATURE_NAMES
from forensics import decode_qr_image
from risk_engine import evaluate_url

st.set_page_config(page_title="PhishGuard — Threat Intelligence",page_icon="🛡️",layout="wide",initial_sidebar_state="collapsed")
DB_PATH = "database/scans.db"
MODEL_PATH = "model/phishing_model.pkl"
SAMPLE_QR_PATH = "sample_quish.png"

def init_db():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            label TEXT,
            confidence REAL,
            scanned_at TEXT,
            risk_score REAL DEFAULT 0.0,
            tier TEXT DEFAULT 'safe',
            input_type TEXT DEFAULT 'url'
        )
    """)
    cursor = conn.execute("PRAGMA table_info(scans)")
    cols = [r[1] for r in cursor.fetchall()]
    if 'risk_score' not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN risk_score REAL DEFAULT 0.0")
    if 'tier' not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN tier TEXT DEFAULT 'safe'")
    if 'input_type' not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN input_type TEXT DEFAULT 'url'")
    conn.commit()
    conn.close()

def save_scan(url, label, confidence, risk_score, tier, input_type="url"):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO scans (url, label, confidence, scanned_at, risk_score, tier, input_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (url, label, confidence, datetime.now().strftime("%Y-%m-%d %H:%M"), risk_score, tier, input_type)
    )
    conn.commit()
    conn.close()

def load_scans():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT id, url, label, risk_score, tier, input_type, scanned_at FROM scans ORDER BY id DESC", conn)
    conn.close()
    return df

@st.cache_resource
def load_model():
    if not os.path.exists(MODEL_PATH):
        st.error("Model file not found. Please run `python train_model.py` first")
        st.stop()
    return joblib.load(MODEL_PATH)

@st.cache_resource
def load_explainer(_model):
    if not SHAP_AVAILABLE:
        return None
    return shap.TreeExplainer(_model)

def shap_for_phishing(explainer, X):
    sv = explainer.shap_values(X)
    if isinstance(sv, list):
        vals = np.asarray(sv[1])[0]
    else:
        sv = np.asarray(sv)
        vals = sv[0, :, 1] if sv.ndim == 3 else sv[0]
    return vals

def to_host(url):
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    host = (urlparse(u).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host

init_db()
model = load_model()
explainer = load_explainer(model)
st.title("🛡️ PhishGuard: Hybrid Threat Intelligence Platform")
st.caption("Random Forest (18 Feats) • Live WHOIS (Port 43) • DNS MX • Levenshtein Distance • OpenCV QR Engine")
st.divider()

tabs = st.tabs([
    "🔍 URL Investigation",
    "📷 Quishing",
    "📊 Analytics"
])
def render_analysis_results(target_url, input_source="url"):
    with st.spinner("Analyzing target across AI and Live Network Forensics..."):
        features = extract_features(to_host(target_url))
        X = pd.DataFrame([features])[FEATURE_NAMES]
        proba = model.predict_proba(X)[0]
        ml_phish_prob = float(proba[1])
        res = evaluate_url(target_url, ml_phish_prob)

    save_scan( url=target_url,label=res['verdict'],confidence=res['risk_score'],risk_score=res['risk_score'],tier=res['tier'],input_type=input_source)

    st.write("")
    left_col, right_col = st.columns([1, 1], gap="large")

    with left_col:
        st.markdown("### AI & Assessment")
        score = int(res['risk_score'])
        if res['tier'] == 'safe':
            st.success(f"#### {res['icon']} {res['verdict']}")
        elif res['tier'] == 'caution':
            st.warning(f"#### {res['icon']} {res['verdict']}")
        else:
            st.error(f"#### {res['icon']} {res['verdict']}")
        st.progress(score / 100)
        st.markdown(f"**Composite Risk Score:** `{score} / 100` &nbsp;|&nbsp; **ML Malicious Probability:** `{res['ml_probability']}%`")
        st.write(res['summary'])
        if res['redirects'].get('is_redirected'):
            st.info(f"🔀 **Redirect Chain Unrolled:** `{res['final_url']}` ({res['redirects']['redirect_count']} hops)")
        st.write("")

        st.markdown("##### Why the ML model said this (SHAP)")
        if explainer is None:
            st.info("Install `shap` (`pip install shap`) to see per-URL ML explanations.")
        else:
            st.caption("Red bars push this hostname toward phishing, green bars toward safe.")
            try:
                vals = shap_for_phishing(explainer, X)
                shap_df = pd.DataFrame({"Feature": FEATURE_NAMES,"Value": [features[f] for f in FEATURE_NAMES],"SHAP": vals})
                shap_df = shap_df[shap_df["SHAP"].abs() > 1e-6]
                shap_df = shap_df.reindex(
                    shap_df["SHAP"].abs().sort_values(ascending=False).index
                ).head(8).sort_values("SHAP", ascending=True)
                shap_df["Label"] = shap_df["Feature"] + " = " + shap_df["Value"].astype(str)
                shap_df["Direction"] = np.where(
                    shap_df["SHAP"] > 0, "Toward phishing", "Toward safe")

                fig_shap = px.bar(shap_df, x="SHAP", y="Label", orientation="h",color="Direction",color_discrete_map={"Toward phishing": "#e74c3c","Toward safe": "#2ecc71"},height=300)
                fig_shap.update_layout(margin=dict(l=10, r=10, t=10, b=10),legend_title_text="",xaxis_title="Impact on phishing probability",yaxis_title="")
                st.plotly_chart(fig_shap, use_container_width=True)
            except Exception as e:
                st.warning(f"SHAP explanation unavailable: {str(e)[:80]}")

    with right_col:
        st.markdown("### Live Forensics")

        t1, t2 = st.columns(2)
        with t1:
            age_days = res['whois'].get('age_days')
            if age_days is not None:
                st.metric("Domain Age", f"{age_days} days", f"{res['whois'].get('age_years', 0)} years")
                st.caption(f"Created: {res['whois'].get('creation_date', 'N/A')}")
            else:
                st.metric("Domain Age", "Unverified", delta_color="inverse")
                st.caption("Private WHOIS registry")
        with t2:
            has_ssl = res['ssl'].get('has_ssl', False)
            if has_ssl:
                st.metric("SSL Certificate", "Trusted", "Encrypted")
                st.caption(f"Issuer: {str(res['ssl'].get('issuer', 'Authority'))[:24]}")
            else:
                st.metric("SSL Certificate", "Invalid / None", delta_color="inverse")
                st.caption("No valid TLS certificate")

        t3, t4 = st.columns(2)
        with t3:
            has_mx = res['dns'].get('has_mx', False)
            if has_mx:
                st.metric("Business Mail (MX)", "Configured", "Active")
                st.caption(f"Host: {res['dns']['mx_records'][0] if res['dns']['mx_records'] else 'Active'}")
            else:
                st.metric("Business Mail (MX)", "None", "No Mail Server", delta_color="inverse")
                st.caption("Common on throwaway domains")
        with t4:
            is_typo = res['typosquatting'].get('is_typosquat', False)
            brand_target = res['typosquatting'].get('targeted_brand')
            has_homo = res['homoglyphs'].get('has_homoglyph', False)
            if is_typo:
                st.metric("Brand Spoofing", f"Mimics {brand_target}", delta_color="inverse")
                st.caption(f"Similarity: {int(res['typosquatting']['similarity']*100)}%")
            elif has_homo:
                st.metric("Brand Spoofing", "Homoglyph Attack", delta_color="inverse")
                st.caption("Punycode / Script spoof")
            else:
                st.metric("Brand Spoofing", "Clean", "No Spoofing")
                st.caption("Standard Latin character set")

        st.divider()
        st.markdown("##### Explainable Evidence List")
        has_flags = False
        if res['dangers']:
            has_flags = True
            for d in res['dangers']:
                st.error(d)
        if res['cautions']:
            has_flags = True
            for c in res['cautions']:
                st.warning(c)
        if res['positives']:
            for p in res['positives']:
                st.success(p)

        if not has_flags:
            st.info("No suspicious structural, network, or visual deception anomalies identified.")
        with st.expander("Raw Registry JSON Viewer"):
            st.json({
                "analyzed_url": target_url,
                "final_destination": res['final_url'],
                "whois_registrar": res['whois'].get('registrar', 'N/A'),
                "whois_created": res['whois'].get('creation_date', 'N/A'),
                "dns_mx_records": res['dns'].get('mx_records', []),
                "ssl_details": res['ssl'],
                "typosquat_details": res['typosquatting'],
                "redirect_hops": res['redirects'].get('redirect_count', 0)
            })

with tabs[0]:
    st.markdown("#### Enter URL to Inspect")
    url_input = st.text_input(
        "Website URL:",
        placeholder="https://example.com/login",
        label_visibility="collapsed"
    )
    st.markdown("**Quick Demo Scenarios:**")
    p1, p2, p3, p4 = st.columns(4)
    demo_url = None
    if p1.button("🟢 Legitimate (google.com)", use_container_width=True):
        demo_url = "https://google.com"
    if p2.button("🔴 Typosquatting (arnazon)", use_container_width=True):
        demo_url = "http://arnazon-support-login.com"
    if p3.button("🔴 Zero-Day Scam (.xyz)", use_container_width=True):
        demo_url = "http://secure-login-paypal.xyz/signin"
    if p4.button("🟡 New Startup (.com)", use_container_width=True):
        demo_url = "http://freshcoffeestartup.com/contact"

    scan_btn = st.button("🚀 Run Multi-Vector Security Scan", type="primary", use_container_width=False)

    active_target = None
    if scan_btn and url_input.strip():
        active_target = url_input.strip()
    elif demo_url:
        active_target = demo_url

    if active_target:
        render_analysis_results(active_target, input_source="url")

with tabs[1]:
    st.markdown("#### Quishing (QR Code Phishing Scanner)")
    st.write("Upload a QR code or load a sample to decode and run live multi-vector forensics on the embedded URL.")

    qr_col_input, qr_col_preview = st.columns([1, 1], gap="medium")
    
    with qr_col_input:
        qr_mode = st.radio("Select QR Input Source:", ["Upload Image File", "Use Camera", "⚡ Load Sample Phishing QR"], horizontal=True)
        
        qr_image_to_process = None
        if qr_mode == "Upload Image File":
            uploaded_file = st.file_uploader("Upload QR Image (PNG, JPG, JPEG):", type=["png", "jpg", "jpeg"])
            if uploaded_file is not None:
                qr_image_to_process = Image.open(uploaded_file)
        elif qr_mode == "Use Camera":
            cam_shot = st.camera_input("Capture QR Code:")
            if cam_shot is not None:
                qr_image_to_process = Image.open(cam_shot)
        else:
            if os.path.exists(SAMPLE_QR_PATH):
                qr_image_to_process = Image.open(SAMPLE_QR_PATH)
                st.info("Loaded pre-configured Quishing demonstration payload (`paypal.xyz` spoof).")

    with qr_col_preview:
        if qr_image_to_process is not None:
            st.image(qr_image_to_process, caption="Target QR Code Matrix", width=220)
            
            with st.spinner("Decoding QR Matrix using OpenCV Computer Vision..."):
                qr_data = decode_qr_image(qr_image_to_process)

            if qr_data['success']:
                decoded_url = qr_data['url']
                st.success(f"🎯 **Decoded Target Payload:** `{decoded_url}`")
                st.write("")
                run_qr_investigation = st.button("🔍 Execute Security Analysis on Decoded URL", type="primary")
            else:
                st.error(f"❌ {qr_data['error']}")
                run_qr_investigation = False
        else:
            st.info("Select an input source on the left to inspect a QR code.")
            run_qr_investigation = False

    if qr_image_to_process is not None and qr_data.get('success') and run_qr_investigation:
        st.divider()
        render_analysis_results(qr_data['url'], input_source="qr")

with tabs[2]:
    st.markdown("#### Security Analytics & Audit Ledger")
    history_df = load_scans()

    if history_df.empty:
        st.info("No audit logs recorded yet. Run an analysis in Tab 1 or Tab 2.")
    else:
        total_count = len(history_df)
        phish_count = len(history_df[history_df['tier'] == 'phishing']) if 'tier' in history_df.columns else 0
        caution_count = len(history_df[history_df['tier'] == 'caution']) if 'tier' in history_df.columns else 0
        safe_count = len(history_df[history_df['tier'] == 'safe']) if 'tier' in history_df.columns else 0

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Scans", total_count)
        m2.metric("Verified Legitimate", safe_count)
        m3.metric("Caution (Unverified)", caution_count, delta_color="off")
        m4.metric("Threats Intercepted", phish_count, delta_color="inverse")

        st.divider()

        c_chart1, c_chart2 = st.columns(2)
        with c_chart1:
            if 'tier' in history_df.columns:
                fig_pie = px.pie(history_df,names='tier',title="Threat Tier Breakdown",color='tier',color_discrete_map={"safe": "#2ecc71","caution": "#f39c12","phishing": "#e74c3c"},hole=0.4)
                fig_pie.update_layout(height=280, margin=dict(l=10, r=10, t=30, b=10))
                st.plotly_chart(fig_pie, use_container_width=True)

        with c_chart2:
            if 'scanned_at' in history_df.columns:
                history_df['date'] = pd.to_datetime(history_df['scanned_at'], format='mixed', errors='coerce').dt.date
                trend = history_df.dropna(subset=['date']).groupby(['date', 'label']).size().reset_index(name='scans')
                fig_bar = px.bar(trend,x='date',y='scans',color='label',title="Telemetry Activity Timeline",barmode='stack',height=280)
                fig_bar.update_layout(margin=dict(l=10, r=10, t=30, b=10))
                st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("##### Historical Audit Ledger")
        st.dataframe(history_df, use_container_width=True, hide_index=True)
        csv = history_df.to_csv(index=False).encode('utf-8')
        st.download_button(label="📥 Export Security Ledger (CSV)",data=csv,file_name="phishguard_audit_telemetry.csv",mime="text/csv")