import argparse
import io
import os
import zipfile
from urllib.parse import urlparse
import joblib
import pandas as pd
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import GroupShuffleSplit
from features import extract_features, FEATURE_NAMES

DATA_DIR = 'data'
MAX_PER_CLASS = 20000
HEADERS = {'User-Agent': 'phishguard-student-project/1.0'}
TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip'
PHISHTANK_URL = 'https://data.phishtank.com/data/online-valid.csv'
OPENPHISH_URL = 'https://openphish.com/feed.txt'

def _get(url, timeout=60):
    r = requests.get(url, headers=HEADERS, timeout=timeout)
    r.raise_for_status()
    return r

def load_tranco(top_n=100000):
    path = os.path.join(DATA_DIR, 'tranco.csv')
    if not os.path.exists(path):
        print("Downloading Tranco list...")
        content = _get(TRANCO_URL, timeout=120).content
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            with z.open(z.namelist()[0]) as f:
                open(path, 'wb').write(f.read())
    df = pd.read_csv(path, header=None, names=['rank', 'domain'], nrows=top_n)
    return df['domain'].astype(str).tolist()

def load_phishing():
    path = os.path.join(DATA_DIR, 'phish.txt')
    if not os.path.exists(path):
        urls = []

        local = os.path.join(DATA_DIR, 'phishtank.csv')
        if os.path.exists(local):
            print("Reading local PhishTank CSV (data/phishtank.csv)...")
            df = pd.read_csv(local)
            urls += df['url'].dropna().tolist()
        else:
            print("data/phishtank.csv not found, trying PhishTank download...")
            key = os.getenv('PHISHTANK_KEY')
            pt_url = (f'https://data.phishtank.com/data/{key}/online-valid.csv'
                      if key else PHISHTANK_URL)
            try:
                df = pd.read_csv(io.StringIO(_get(pt_url, timeout=120).text))
                urls += df['url'].dropna().tolist()
            except Exception as e:
                print(f"PhishTank failed ({e})")
        try:
            print("Downloading OpenPhish feed...")
            urls += _get(OPENPHISH_URL).text.splitlines()
        except Exception as e:
            print(f"OpenPhish failed ({e})")

        urls = sorted({u.strip() for u in urls if u.strip()})
        if not urls:
            raise SystemExit("No phishing data found. Put the PhishTank CSV "
                             "at data/phishtank.csv and rerun.")
        open(path, 'w', encoding='utf-8').write('\n'.join(urls))
    return open(path, encoding='utf-8').read().splitlines()


def hostname_of(url):
    u = url if url.startswith(('http://', 'https://')) else 'http://' + url
    host = (urlparse(u).hostname or '').lower()
    return host[4:] if host.startswith('www.') else host


def build_dataset(full_urls=False):
    os.makedirs(DATA_DIR, exist_ok=True)
    legit_domains = load_tranco()
    phish_urls = load_phishing()
    print(f"Loaded {len(phish_urls)} unique phishing URLs")

    if full_urls:
        legit = [f'https://{d}' for d in legit_domains]
        phish = phish_urls
    else:
        legit = legit_domains
        phish = [hostname_of(u) for u in phish_urls]

    phish = [p for p in dict.fromkeys(phish) if p]
    legit = [l for l in dict.fromkeys(legit) if l]
    print(f"Unique phishing {'URLs' if full_urls else 'hostnames'}: {len(phish)}")

    n = min(MAX_PER_CLASS, len(legit), len(phish))
    legit = pd.Series(legit).sample(n, random_state=42).tolist()
    phish = pd.Series(phish).sample(n, random_state=42).tolist()
    print(f"Using {len(legit)} legitimate and {len(phish)} phishing samples")

    rows = []
    for label, urls in ((0, legit), (1, phish)):
        for u in urls:
            f = extract_features(u)
            f['label'] = label
            f['host'] = hostname_of(u)
            rows.append(f)
    return pd.DataFrame(rows)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--full-urls', action='store_true',
                        help='train on full URLs (path/query included)')
    args = parser.parse_args()

    df = build_dataset(full_urls=args.full_urls)
    print(f"Dataset shape: {df.shape}")
    print(df['label'].value_counts().to_string())

    X, y, groups = df[FEATURE_NAMES], df['label'], df['host']

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(splitter.split(X, y, groups))
    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    model = RandomForestClassifier(
        n_estimators=250, max_depth=14, class_weight='balanced',
        random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"\nModel Accuracy: {accuracy_score(y_test, y_pred):.4%}")
    print(classification_report(y_test, y_pred,
                                target_names=['Legitimate', 'Phishing']))

    imp = pd.Series(model.feature_importances_, index=FEATURE_NAMES)
    print("\nTop 8 Most Discriminative Features:")
    print(imp.sort_values(ascending=False).head(8).to_string())

    os.makedirs('model', exist_ok=True)
    joblib.dump(model, 'model/phishing_model.pkl')
    print("\nModel saved to model/phishing_model.pkl")


if __name__ == '__main__':
    main()