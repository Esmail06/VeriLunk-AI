# VeriLunk AI

An English, professional web interface for scanning website URLs and displaying an explainable risk assessment. It is designed as a minimum viable product (MVP) for an **AI-powered Phishing Website Detection System**.

## Run locally

No installation is needed: open `index.html` in any modern browser. You can also run it locally from the project folder:

```powershell
python -m http.server 8080
```

Then open `http://localhost:8080`.

## Run the reachability API

The VeriLunk AI API safely checks whether a public URL responds to a request. It does not open the link in the user's browser, does not follow redirects, rejects local/private network addresses, limits request time, and applies a basic request rate limit.

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

When developing locally, open `http://127.0.0.1:8000` after starting the API. It serves both the frontend and the API, so the reachability check works without extra configuration.

For production, deploy the `backend` folder to a Python service such as Render or Railway. Set `ALLOWED_ORIGINS` to your GitHub Pages URL, then set `API_BASE_URL` in `app.js` to the deployed API URL before publishing the frontend.

## What does the prototype scan?

- HTTPS, URL length, and domain complexity.
- IP addresses used in place of domains, excessive subdomains, and hyphens.
- The `@` symbol and internationalized domain encoding (`xn--`).
- Words commonly associated with phishing, such as `verify`, `login`, and `password`.
- A small local trusted-domain list for demonstration purposes.

The app does not visit the entered link or transmit it to any external service. The result is based on local structural analysis and is an assistive indicator, not a final security decision.

## Project structure

| File | Responsibility |
|---|---|
| `index.html` | English interface and user experience |
| `styles.css` | Responsive design and color system |
| `app.js` | Feature extraction, scoring, and decision explanation |
| `backend/main.py` | FastAPI reachability service with SSRF protections |
| `backend/requirements.txt` | Python runtime dependencies |

## Production roadmap

1. Collect a trustworthy and balanced dataset of legitimate and phishing URLs.
2. Train a model such as XGBoost or Random Forest on URL, DNS, and SSL features.
3. Build a secure FastAPI service to load the model and record metrics without retaining sensitive URLs.
4. Integrate Google Safe Browsing or VirusTotal with secure API-key handling and privacy controls.
5. Add domain-age checks, SSL certificate validation, DNS reputation, and website screenshot analysis using computer vision.
6. Continuously measure accuracy, F1 score, and false positives before deploying any automated blocking decision.
