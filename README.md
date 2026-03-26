# OctaneDrop LAN

OctaneDrop LAN is a self-hosted secure file sharer for a local Wi‑Fi or wired LAN.
It runs as a small FastAPI web app, uses **#ff7300** as the UI theme, and is meant to be opened from any phone, tablet, or laptop connected to the same network.

This repo is ready for a **public GitHub repository + GitHub Releases** workflow so anyone can download a Windows `.exe` and run their own LAN host.

## What it does

- Password-protected web dashboard
- Local-network-only request filtering based on detected private subnets
- Encrypted-at-rest file storage using AES-GCM
- **Streamed encrypted uploads/downloads**, so large files do not need to be loaded fully into RAM
- **1 TiB per-file limit** by default
- CSRF protection on state-changing actions
- Signed temporary share links for downloads
- Login and upload rate limiting
- SHA-256 checksum shown for every file
- Works across phones, tablets, and laptops on the same Wi‑Fi
- Instant file-list updates over WebSockets when another device uploads or deletes a file
- Optional auto-open of the local browser when run as a bundled desktop executable
- Auto-generated local HTTPS certificates for source runs and the packaged Windows EXE
- One-click CA download endpoint for other LAN devices that need to trust the local certificate

## Hosting model

This app is a **single host + many clients** design:

- One machine runs the OctaneDrop server.
- Everyone else on the same Wi‑Fi/LAN opens that host's URL in a browser.
- Multiple people can use it at the same time.
- If the host machine turns off, sleeps, or leaves the network, the app goes offline until it comes back.

Good always-on hosts:

- Raspberry Pi
- NAS
- Mini PC / homelab box
- Spare laptop that stays on

## Project structure

```text
lan_file_sharer/
├── .github/
│   └── workflows/
│       └── build-windows-release.yml
├── app/
│   ├── config.py
│   ├── db.py
│   ├── main.py
│   ├── network.py
│   ├── security.py
│   ├── tls.py
│   ├── static/
│   │   ├── app.js
│   │   ├── favicon.ico
│   │   ├── favicon.png
│   │   ├── favicon.svg
│   │   └── styles.css
│   └── templates/
│       ├── base.html
│       ├── index.html
│       └── login.html
├── data/
│   └── storage/
├── packaging/
│   └── octanedrop.ico
├── build_windows_exe.bat
├── build_windows_exe.ps1
├── launcher.py
├── LICENSE
├── orange_drop_lan.spec
├── requirements-build.txt
├── requirements.txt
└── run.py
```

## Quick start from source

### 1) Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

On first run, OctaneDrop creates its own local session secret, at-rest encryption key, database, and local TLS files inside the app data directory.

### 3) Create the admin account

```bash
python run.py create-admin --username admin
```

You will be prompted for a password. Use a long one.

### 4) Start the app

```bash
python run.py serve --host 0.0.0.0 --port 8765 --open-browser
```

Open the printed LAN URL from another device connected to the same Wi‑Fi.

Example:

```text
https://192.168.1.24:8765
```

## Automatic local HTTPS (default)

`python run.py serve` and the packaged Windows EXE now auto-generate a local CA + server certificate and serve the app over HTTPS by default.

What happens automatically:

- a persistent local CA is created under the app data directory
- a fresh server certificate is generated for `localhost`, the detected LAN IP, and the host machine name
- on Windows, the EXE/source launcher tries to add the CA to the **current user** trusted root store so the host browser stops showing the not-secure warning
- other LAN devices can download the CA once from `/ca-cert.pem` and trust it on that device

Disable auto-generated HTTPS if you explicitly want plain HTTP:

```bash
python run.py serve --host 0.0.0.0 --port 8765 --no-auto-tls
```

Or provide your own certificate files:

```bash
python run.py serve \
  --host 0.0.0.0 \
  --port 8765 \
  --ssl-certfile cert.pem \
  --ssl-keyfile key.pem
```

## Environment variables

These are optional.

| Variable | Purpose | Default |
|---|---|---|
| `FILESHARE_APP_NAME` | App name in the UI | `OctaneDrop LAN` |
| `FILESHARE_HOST` | Bind host | `0.0.0.0` |
| `FILESHARE_PORT` | Bind port | `8765` |
| `FILESHARE_MAX_UPLOAD_BYTES` | Max size per uploaded file | `1099511627776` |
| `FILESHARE_MAX_UPLOAD_MB` | Legacy alternate upload limit | unset |
| `FILESHARE_STREAM_CHUNK_MB` | Encryption stream chunk size | `8` |
| `FILESHARE_ALLOWED_SUBNETS` | Comma-separated CIDRs to allow | auto-detected |
| `FILESHARE_SHARE_TOKEN_TTL_SECONDS` | Temporary link lifetime | `600` |
| `FILESHARE_SESSION_MAX_AGE_SECONDS` | Session length | `43200` |
| `FILESHARE_PUBLIC_BASE_URL` | Force share links to use a specific base URL | unset |
| `FILESHARE_DATA_DIR` | Override where the database, secrets, and uploads are stored | platform default |
| `FILESHARE_AUTO_OPEN_BROWSER` | Set to `0` to stop the bundled executable from opening a browser automatically | `1` |

## Windows EXE bundling

This project is bundling-ready with PyInstaller.

### Build locally on Windows

PowerShell:

```powershell
./build_windows_exe.ps1
```

Batch:

```bat
build_windows_exe.bat
```

Or manually:

```powershell
python -m pip install -r requirements-build.txt
python -m PyInstaller --noconfirm --clean orange_drop_lan.spec
```

The output executable will be:

```text
dist\OctaneDropLAN.exe
```

### Where the EXE stores data

When frozen as an EXE, OctaneDrop LAN stores its database, encryption key, session secret, uploaded files, and generated local TLS certificates here by default:

```text
%LOCALAPPDATA%\OctaneDropLAN
```

That keeps data persistent even though the executable itself is bundled.

## GitHub repo + Releases workflow

This repo is already set up for the standard public-download flow:

1. Create a new GitHub repository.
2. Push this project to the repository.
3. Open the **Actions** tab and allow workflows if GitHub asks.
4. Create a version tag and push it:

```bash
git tag v1.0.0
git push origin v1.0.0
```

5. The workflow in `.github/workflows/build-windows-release.yml` will:
   - build `OctaneDropLAN.exe` on a GitHub-hosted Windows runner
   - generate a SHA-256 checksum file
   - upload the EXE as a workflow artifact
   - publish both files to **GitHub Releases** for tag builds

After that, users can download from your repo’s Releases page, or from the latest-release pattern:

```text
https://github.com/<owner>/<repo>/releases/latest
```

### Important distribution note

Do **not** commit the built `.exe` into the repository itself.
Keep source code in the repo, and distribute binaries through **GitHub Releases**.

## Can anyone use the EXE?

Yes. Any Windows user can download the EXE and run their own local instance.

What that means in practice:

- the downloader becomes the **host** for their own LAN share
- other devices on **their** Wi‑Fi can open the host’s LAN URL in a browser
- it is still a local-network app, not a cloud multi-tenant service

## SmartScreen / code signing

An unsigned EXE may show a Windows SmartScreen warning when downloaded or launched.
That does **not** mean the app is malicious, but it does mean Windows doesn’t yet trust the publisher identity.

For smoother distribution, sign release builds with a code-signing certificate.

## Notes

- Stored files are encrypted on disk, but the encryption key is stored locally in the data directory. Protect the host machine itself.
- Share links are short-lived but can be used by anyone on the LAN until they expire.
- Browsers on other phones/laptops may still warn until that device installs the local CA from `/ca-cert.pem`.
- A 1 TiB limit still requires enough free disk for the temporary upload file plus the encrypted destination file during upload. Use NTFS or another filesystem that supports files larger than 4 GB.
- If your network uses a different subnet than the one detected automatically, set `FILESHARE_ALLOWED_SUBNETS` manually.
- If share links should always point at a specific hostname or IP, set `FILESHARE_PUBLIC_BASE_URL`.
- Live refresh works per running app instance. If you later scale this across multiple app replicas, use a shared pub/sub layer such as Redis.

Example:

```bash
export FILESHARE_PUBLIC_BASE_URL="https://192.168.1.24:8765"
```

## Resetting the admin password

Run the same command again:

```bash
python run.py create-admin --username admin
```

It updates the password hash for that username.
