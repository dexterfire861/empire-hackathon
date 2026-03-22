# empire-hackathon
Agent that does research online for you about where your data is exposed in relation to data privacy. Made for Empire Hacks 2026

change the API key in .env for claude API
run python -m uvicorn Leakipedia.main:app --reload

## Results frontend

The `/results` page now has a dedicated React + Vite frontend under `frontend/`.

### First-time setup

1. `cd frontend`
2. `npm install`

### Local frontend development

1. Start FastAPI: `python -m uvicorn Leakipedia.main:app --reload`
2. In another terminal: `cd frontend && npm run dev`
3. Open the Vite app and keep using the same `scan_id` query param contract.

The Vite dev server proxies `/scan`, `/static`, and `/extension` back to FastAPI so the live results workspace uses the existing backend endpoints.

### Production build for FastAPI

1. `cd frontend`
2. `npm run build`

The build outputs to `Leakipedia/static/results-app/`, and FastAPI serves that bundle from `/results`. If the bundle is missing, FastAPI falls back to the legacy static results page.
