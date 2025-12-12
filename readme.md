# Secure Login (AES-GCM + RSA-OAEP)

## Overview

Hybrid encryption demo: browser encrypts credentials using AES-GCM (random key), AES key encrypted by RSA-OAEP (SHA-1) with server public key. Server decrypts RSA -> AES and authenticates.

## Files

- public/index.html : frontend
- api.php : backend
- router.php : local router
- public.pem : public key (place at project root)
- private.pem : private key (place at project root, DO NOT COMMIT)
- .env : config (copy from .env.example)
- composer.json : dependencies
- schema.sql : DB schema and test user

## Setup

1. Clone project
2. Run `composer install`
3. Create `.env` from `.env.example` and set DB credentials and PRIVATE_KEY_PATH (e.g. PRIVATE_KEY_PATH=private.pem)
4. Generate RSA keypair (recommended)
   - Using Git Bash:
     ```
     openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
     openssl rsa -pubout -in private.pem -out public.pem
     ```
   - Place both `private.pem` and `public.pem` in project root (same level as router.php)
   - Ensure `public.pem` is accessible at http://localhost:8000/public.pem
5. Import DB: `mysql -u root -p < schema.sql` (adjust user)
6. Start server:
   `cd project_root
php -S localhost:8000 router.php`

7. Open `http://localhost:8000` in browser
8. Test credentials:

- username: `testuser`
- password: `Test@1234`
