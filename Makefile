.PHONY: up down test demo audit serve-api serve-ui serve ui-install

up:
	docker compose up -d

down:
	docker compose down

test:
	pytest tests/ -v

demo:
	powershell -File run_demo.ps1

audit:
	jwtaudit audit --base-url http://localhost:4000

# --- Web app (JWT Audit Lab UI) -------------------------------------------
ui-install:
	cd auditor/static && npm install

serve-api:
	cd auditor && uvicorn app:app --host 0.0.0.0 --port 8001 --reload

serve-ui:
	cd auditor/static && npm run dev

serve:
	powershell -File serve_web.ps1
