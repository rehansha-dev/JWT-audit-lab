#!/bin/bash
echo "Testing JWT Audit Lab Starter Kit..."
echo ""

echo "1. Login as alice..."
TOKEN=$(curl -s -X POST http://localhost:4000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "   Token: ${TOKEN:0:30}..."
echo ""

echo "2. GET /me..."
curl -s http://localhost:4000/me \
  -H "Authorization: Bearer $TOKEN"
echo ""

echo "3. GET /admin as alice (should be 403)..."
curl -s -o /dev/null -w "   Status: %{http_code}\n" \
  http://localhost:4000/admin \
  -H "Authorization: Bearer $TOKEN"
echo ""

echo "Done. Point JWT Audit Lab at http://localhost:4000"
