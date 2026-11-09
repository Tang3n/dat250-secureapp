# DAT250 SecureApp — UiS Student Project Portal

## 1. Purpose
This repository contains a local-only lab web application for DAT250 Information and Software Security. It is designed for safe classroom use on your own machine.

## 2. Required tools
- Docker Desktop
- Git
- A web browser
- VS Code (optional)

## 3. Quick start
```bash
git clone <repo>
cd dat250-secureapp
docker compose down -v
docker compose up --build
```

## 4. URLs
- App: [http://localhost:18181](http://localhost:18181)
- MailHog inbox: [http://localhost:8025](http://localhost:8025)
- Optional database admin UI: [http://localhost:8081](http://localhost:8081), if enabled
- API docs (if available in this lab build): [http://localhost:18181/docs](http://localhost:18181/docs)

## Running the app

```bash
docker compose down -v
docker compose up --build
```

Main URLs:
- Main app: `http://localhost:18181`
- MailHog: `http://localhost:8025`
- Optional database admin UI: `http://localhost:8081`, if enabled

If phpPgAdmin is enabled, use:
- Server/Host: `db`
- Port: `5432`
- Database: `dat250`
- Username: `dat250`
- Password: `dat250`

## Security fixes (DAT250 Assignment 2)

This fork remediates the vulnerabilities reported in Assignment 1:

| ID | Vulnerability | Category | Main changes |
|---|---|---|---|
| F1 | Privilege escalation via mass assignment on `POST /profile/update` | Broken Access Control | `routes/profile_routes.py`, `templates/profile.html` |
| F2 | Missing server-side role checks on admin endpoints | Broken Access Control | `auth.py` (`require_role`), `routes/admin_routes.py` |
| F3 | IDOR on `GET /grades/{id}` and `GET /messages/{id}` | Broken Access Control | `routes/grade_routes.py`, `routes/message_routes.py` |
| F4 | SQL injection in `GET /admin/search-users` | Injection | `routes/admin_routes.py` |
| F5 | Unsalted SHA-256 password storage | Cryptographic Storage | `auth.py` (Argon2id), `db/seed.sql` |
| F6 | Weak session cookie, account enumeration, predictable/replayable reset tokens | Broken Authentication | `auth.py`, `routes/auth_routes.py`, `config.py` |

New settings (in `.env.example`, which docker-compose loads): `SESSION_MAX_AGE_SECONDS`, `RESET_TOKEN_TTL_SECONDS`,
`COOKIE_SECURE` (set to `true` when the app is served over HTTPS).

### Running the security regression tests

The tests in `tests/` talk to a running instance over HTTP, exactly like the
original exploits did, and read the database and MailHog only to check state.
Each finding has negative tests (the Assignment 1 exploit must fail) and
positive tests (legitimate use still works).

```bash
# 1. Start a fresh instance (the tests expect the seeded data)
docker compose down -v
docker compose up --build -d

# 2. Install the test dependencies (Python 3.10+)
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements.txt

# 3. Run the tests
.venv/bin/pytest tests -v
```

Defaults target `http://localhost:18181`, MailHog on `http://localhost:8025` and
PostgreSQL on `localhost:5432`; override them with `BASE_URL`, `MAILHOG_URL`
and `TEST_DATABASE_URL` if needed.

## 5. Test users
Use these accounts in the local lab environment:

- admin@dat250.local / Admin123
- teacher@dat250.local / Teacher123
- ta@dat250.local / TA123
- alice@student.uis.no / Alice123
- bob@student.uis.no / Bob123
- charlie@student.uis.no / Charlie123

## 6. Resetting the lab
```bash
docker compose down -v
docker compose up --build
```

Or use helper scripts (run from this project folder):
- macOS/Linux: `./dat250.sh reset` — wipes DB volumes and starts again (foreground).
- macOS/Linux: `./dat250.sh rebuild` — pulls images, rebuilds the backend image without cache, recreates containers in the background (keeps DB volume).
- Windows PowerShell: `.\dat250.ps1 reset` or `.\dat250.ps1 rebuild` — same meanings as above.

## 7. Ethical rules
- Use this lab only on your own local machine.
- Only test your own DAT250 lab instance.
- Do not test, scan, or attack UiS systems or any public system.
- Do not scan public IP addresses or other students' machines.
- Do not deploy this application publicly.

Students may use external course-approved tools (for example browser DevTools and interception proxies) as required by the course assignments.

## Running with Kali Linux

### Mode A: App and tools on the same machine

Use:
`http://localhost:18181`

### Mode B: App on physical laptop, Kali in VM

- Keep the app running on the host laptop with Docker.
- Find the host IP address reachable from Kali.
- Try the host-only adapter IP, bridged adapter IP, or default gateway depending on virtualization mode.
- Open from Kali:
  `http://<HOST-IP>:18181`

### Mode C: App in one VM, Kali in another VM

- Put both VMs on the same virtual network.
- Bridged or host-only networking is usually easiest.
- Start Docker inside the target VM.
- Find the target VM IP:
  `ip -4 addr`
- From Kali, open:
  `http://<TARGET-VM-IP>:18181`

## 8. Troubleshooting
- Docker not running: start Docker Desktop first.
- Port already in use: stop other services on 18181/8025/5432.
- App not updated: run `docker compose down -v` and rebuild.
- Database issues: use the reset command to recreate data.

## 9. What students submit
- Security test plan
- Findings with evidence
- Root cause explanation
- Code/config fix for selected issues
- Retest evidence
