sudo chown -R $(whoami) .

# Cifratura
curl -X POST http://localhost:8080/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"password_segreta"}'

# Decifratura (usa il JSON restituito da encrypt)
curl -X POST http://localhost:8080/decrypt \
  -H 'Content-Type: application/json' \
  -d '{"data": { ... }}'