# 🛡️ PhishGuard

**An explainable phishing and quishing (QR phishing) detector that shows you *why* a link is risky, not just a verdict.**

Most student phishing detectors only look at the text of a URL. PhishGuard also checks the domain itself, then gives a 0-100 risk score with a plain-language breakdown of every red and green flag.

## What it does

- **Scans URLs or QR codes.** Paste a link, upload a QR image or use your camera. PhishGuard decodes the QR with OpenCV and analyses the hidden URL.
- **Unmasks redirects.** It follows redirect chains so shortened links can't hide their real destination.
- **Checks the domain live:**
  - WHOIS lookup for domain age (brand-new domains are riskier)
  - SSL certificate validity and issuer
  - DNS MX records (throwaway domains rarely set up email)
- **Catches impersonation:**
  - Typosquatting against well-known brands (`paypa1`, `amaz0n`, `paypal-verify`)
  - Homoglyph and Punycode attacks (Cyrillic letters pretending to be Latin ones)
- **Explains itself on two levels:**
  - SHAP values show which features pushed the ML model toward "phishing" or "safe" for each scan
  - An evidence list shows every forensic finding that moved the score
- **Keeps an audit log** of scans in SQLite, with an analytics tab and CSV export.

| Score | Verdict |
|-------|---------|
| 0-30 | 🟢 Low risk |
| 31-65 | 🟡 Caution |
| 66-100 | 🔴 High risk (phishing) |

## How the score works

A Random Forest looks at 18 lexical features of the hostname (length, entropy, dots, hyphens, digits, suspicious keywords and TLDs, and so on) and contributes up to 40 points. The forensic checks then add or subtract points, so no single signal decides the outcome. A young domain on its own, for example, won't be labelled phishing.

The weights are hand-picked heuristics, so treat the score as a triage aid rather than a calibrated probability.

## The model

- **Phishing data:** [PhishTank](https://phishtank.org) and [OpenPhish](https://openphish.com) feeds
- **Legitimate data:** the top 100,000 domains from the [Tranco](https://tranco-list.eu) ranking
- **Setup:** 20,000 hostnames per class, split 80/20 **by hostname** so no domain appears in both train and test
- **Held-out result:** about 89% accuracy (phishing precision 0.93, recall 0.84)

Tranco lists only domains, so the model is trained on bare hostnames (with `www.` removed) rather than full URLs. That keeps the comparison fair, because phishing URLs would otherwise differ from legitimate ones just by having a path. The live forensics cover the rest.

## Project structure

```
├── app.py            # Streamlit web interface
├── features.py       # Hostname feature extraction for the ML model
├── forensics.py      # WHOIS, DNS, SSL, redirects, typosquatting, homoglyphs, QR decoding
├── risk_engine.py    # Combines ML + forensics into the final score
├── train_model.py    # Trains and saves the Random Forest
├── requirements.txt
├── LICENSE
└── PROJECT_REPORT.md # Original project proposal
```

## Getting started

```bash
git clone https://github.com/T-Hub06/PhishGuard.git
cd PhishGuard
pip install -r requirements.txt
```

**1. Add the training data.** Download the PhishTank CSV (`online-valid.csv`) from [phishtank.org/developer_info.php](https://phishtank.org/developer_info.php) and save it as `data/phishtank.csv`. The script downloads the Tranco list and the OpenPhish feed automatically.

**2. Train the model** (creates `model/phishing_model.pkl`):

```bash
python train_model.py
```

**3. Launch the app:**

```bash
streamlit run app.py
```

## Tech stack

Python · Streamlit · scikit-learn · SHAP · pandas · Plotly · OpenCV · python-whois · dnspython · SQLite

## Limitations

- **Hostname-only ML.** It can't see paths or query strings, and it misses roughly 1 in 6 phishing hostnames, mostly pages hosted on compromised or free-hosting domains that look ordinary.
- **Dataset bias.** Tranco covers popular sites only, so lesser-known legitimate domains may be scored more suspiciously. The live checks help offset this.
- **Live checks need internet.** WHOIS data is sometimes private or rate-limited, and many phishing links are taken down quickly.
- **"Safe" is not a guarantee.** An old or newly registered but harmless-looking domain can still be malicious.
- **Fixed brand list** for typosquatting, and heuristic scoring weights.
- PhishTank and Tranco change daily, so exact numbers will differ between downloads.

## Author

**Tushar Joshi**, BCA (AI & Data Science), Graphic Era (Deemed to be University), Dehradun

## License

MIT. See the [LICENSE](LICENSE) file.
