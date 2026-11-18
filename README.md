# imap-mcp

Give Claude access to your own mailbox: **iCloud Mail** or any other IMAP account, plus read-only
**iCloud calendars**. It's a small Python MCP server that you host yourself. Claude can search
and read your mail and save drafts. If you enable it per account, Claude can also organize
(move, flag, file into folders). It **cannot send** unless you explicitly turn sending on, and it
can never permanently delete mail.

It's built to run on an always-on Mac (a Mac mini works well) and to be used from **claude.ai**
(web, desktop, mobile) as a custom connector. Claude's cloud reaches it through a
**Tailscale Funnel** HTTPS URL, and only your GitHub login can get in.

```
claude.ai / Claude apps ──HTTPS──▶ Tailscale Funnel ──▶ imap-mcp on your Mac ──IMAPS/CalDAV──▶ iCloud
        (Anthropic cloud)     https://mac.tailnet.ts.net   127.0.0.1:8770
                                                  │
                                       GitHub OAuth login, allowlisted to YOUR GitHub username
```

## What Claude can do

| Tool | What it does | Enabled |
|---|---|---|
| `list_accounts`, `list_folders` | Mailboxes and folders with unread counts | always |
| `search_messages` | Search a folder by sender, recipient, subject, full text, dates, unread or flagged | always |
| `read_message`, `get_thread` | Read a message without marking it read, or a whole conversation | always |
| `get_attachment` | Open an attachment: **PDFs** as text (scanned PDFs, or `mode="images"`, as page images Claude can see), **images** (JPEG/PNG/GIF/WebP), and text files (.ics, .csv, .json…) | always |
| `create_draft` | Save a draft (new or reply) to Drafts. **Nothing is sent**; you send it from Mail | always |
| `move_message`, `set_flags` | Move to a folder, archive or trash; mark read/unread or flagged | `organize: true` |
| `create_folder`, `rename_folder`, `delete_folder` | Manage your own folders. System folders are refused; only **empty** folders can be deleted | `organize: true` |
| `move_by_search`, `bulk_move_status` | Bulk-move by date range or sender as a background job. Always a dry run (count) first, then a confirmed run | `organize: true` |
| `list_calendars`, `list_events`, `get_event` | Calendars, events (recurring ones expanded), attendees | `calendars:` block |
| `send_message`, `send_draft` | Actually send mail | **off** (`IMAP_MCP_ENABLE_SEND=true`) |

## Security model

- **Your passwords never go into config, environment variables, or chat.** Each one is a file
  (mode 600) in `~/.config/imap-mcp/secrets/`, written by `./set-secret.sh`, which reads it at a
  hidden prompt. Don't paste passwords into Claude; type them into `set-secret.sh` yourself.
- **Use an app-specific password**, never your Apple Account password. Revoking it at
  [account.apple.com](https://account.apple.com) cuts Claude off immediately. (Note: an iCloud
  app-specific password also works for SMTP, contacts and calendars. This server only uses IMAP,
  read-only CalDAV, and SMTP if you enable sending.)
- **Only your GitHub login gets in.** The URL is public. The server requires a GitHub OAuth
  login and rejects every GitHub user not listed in `IMAP_MCP_ALLOWED_GITHUB_LOGINS`. It
  refuses to start if that list is empty.
- **Capabilities are opt-in.** A disabled capability's tools don't exist at all. Calendars are
  read-only in the code itself: the CalDAV client can only send `PROPFIND`/`REPORT`.
- **Email is untrusted input.** The server tells Claude never to follow instructions found in
  an email. Every write (draft, move, flags, folders) is appended to
  `~/.config/imap-mcp/data/audit.log`.

---

## Setup on a Mac mini (remote mode, for claude.ai)

About 30 minutes. You need: the Mac (always on), an Apple Account with iCloud Mail, a free
GitHub account, and a free Tailscale account.

### 1. Keep the Mac awake

System Settings → Energy → turn on **Prevent automatic sleeping when the display is off**, and
**Start up automatically after a power failure**. The server runs as your user, so also turn on
automatic login (System Settings → Users & Groups), or it stops when you log out.

### 2. Install and configure

```bash
brew install python@3.12 git
git clone https://github.com/g-maponus/imap-mcp.git ~/imap-mcp
cd ~/imap-mcp
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt

mkdir -p ~/.config/imap-mcp
cp accounts.example.yaml ~/.config/imap-mcp/accounts.yaml
open -e ~/.config/imap-mcp/accounts.yaml     # replace you@icloud.com and Your Name
```

In `accounts.yaml`, list under `send_as` every address you might want drafts to come from
(e.g. both `@icloud.com` and `@me.com`).

### 3. iCloud app-specific password

At [account.apple.com](https://account.apple.com) → Sign-In and Security → **App-Specific
Passwords** → `+`, name it `imap-mcp`. Then store it:

```bash
./set-secret.sh icloud-app-password       # paste it at the hidden prompt
```

### 4. Public HTTPS URL with Tailscale Funnel

Install Tailscale on the Mac ([tailscale.com/download](https://tailscale.com/download)) and sign
in. Then:

```bash
alias tailscale=/Applications/Tailscale.app/Contents/MacOS/Tailscale   # if `tailscale` isn't on PATH
tailscale funnel --bg 8770
tailscale funnel status          # shows your URL: https://<machine>.<tailnet>.ts.net
```

If it prints a link to enable HTTPS certificates or Funnel for your tailnet, open it, approve,
and run the command again. Write down the `https://….ts.net` URL. That's your **BASE_URL**.
Funnel is persistent: it survives reboots.

### 5. GitHub OAuth App (the login gate)

GitHub → Settings → Developer settings → **OAuth Apps** → New OAuth App:

- Application name: `imap-mcp`
- Homepage URL: your BASE_URL
- Authorization callback URL: **BASE_URL + `/auth/callback`**

Create it, copy the **Client ID**, then **Generate a new client secret**, and store the
secrets:

```bash
./set-secret.sh github-client-secret      # paste the client secret
./set-secret.sh --generate jwt-key        # random key that signs Claude's tokens
```

### 6. Run it as a service (launchd)

```bash
sed -e "s|__REPO__|$HOME/imap-mcp|g" \
    -e "s|https://__MACHINE__.__TAILNET__.ts.net|https://YOUR-MACHINE.YOUR-TAILNET.ts.net|" \
    -e "s|__GITHUB_CLIENT_ID__|YOUR_CLIENT_ID|" \
    -e "s|__YOUR_GITHUB_LOGIN__|your-github-username|" \
    macos/co.imap-mcp.plist > ~/Library/LaunchAgents/co.imap-mcp.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/co.imap-mcp.plist

tail -f /tmp/imap-mcp.log                 # expect: transport=http capabilities: read+draft +organize…
curl -s https://YOUR-MACHINE.YOUR-TAILNET.ts.net/health   # {"status":"ok","accounts":{"icloud":"ok",…}}
```

`/health` returns 503 if the iCloud login fails. Check the app-specific password and
`username` in that case.

### 7. Connect Claude

claude.ai → Settings → **Connectors** → Add custom connector → URL: **BASE_URL + `/mcp`**.
Click Connect, choose your GitHub account in the picker, and approve. Then start a **new** chat
and ask: *"list my mail accounts"*. The connector is tied to your Claude account, so it also
shows up in Claude's other apps.

### Day-to-day

| Task | Command |
|---|---|
| Restart (after editing `accounts.yaml` or the code) | `launchctl kickstart -k gui/$(id -u)/co.imap-mcp` |
| Stop / start | `launchctl bootout gui/$(id -u)/co.imap-mcp` / `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/co.imap-mcp.plist` |
| Logs | `tail -f /tmp/imap-mcp.log` (lists every `tools/list` and `tools/call`) |
| What Claude changed | `~/.config/imap-mcp/data/audit.log` |
| Update | `git pull && .venv/bin/pip install -r requirements.txt`, then restart |
| Cut Claude off | revoke the app-specific password at account.apple.com, or `tailscale funnel reset` |

---

## Optional: local mode (Claude Code / Claude Desktop on the same Mac)

No URL, no OAuth. Claude starts the server itself over stdio. Steps 2–3 above are enough:

```bash
claude mcp add --scope user imap -- ~/imap-mcp/.venv/bin/python ~/imap-mcp/app/server.py
```

`IMAP_MCP_TRANSPORT` defaults to `stdio`. You can use both modes side by side.

## Configuration reference

| Env var | Default | |
|---|---|---|
| `IMAP_MCP_TRANSPORT` | `stdio` | `http` for remote mode |
| `IMAP_MCP_BASE_URL` | — | http: public URL, no trailing `/mcp` |
| `IMAP_MCP_GITHUB_CLIENT_ID` | — | http: GitHub OAuth App client ID |
| `IMAP_MCP_ALLOWED_GITHUB_LOGINS` | — | http: comma-separated GitHub usernames allowed in |
| `IMAP_MCP_HOST` / `IMAP_MCP_PORT` | `127.0.0.1` / `8770` | http listener |
| `IMAP_MCP_ACCOUNTS` | `~/.config/imap-mcp/accounts.yaml` | |
| `IMAP_MCP_SECRETS` | `~/.config/imap-mcp/secrets` | one file per secret |
| `IMAP_MCP_DATA` | `~/.config/imap-mcp/data` | audit log |
| `IMAP_MCP_ENABLE_ORGANIZE` | `false` | organize tools on **all** accounts (or per account: `organize: true`) |
| `IMAP_MCP_ENABLE_SEND` | `false` | registers `send_message` / `send_draft`, limited to 20/hour and 25 recipients |
| `IMAP_MCP_TZ` | system zone | timezone for calendar results, e.g. `America/Toronto` |
| `IMAP_MCP_NTFY_URL` | — | optional ntfy topic URL, alerted on sends and bulk moves |

## Known quirks (already handled)

- **iCloud has no IMAP `MOVE`.** Moves are done as COPY + delete of exactly those messages
  (never a blanket expunge). Large COPY batches time out half-done and iCloud then throttles
  the account ("Server Busy") for minutes, so bulk moves go in chunks of 25. A half-done chunk
  is reconciled by Message-ID before retrying, so you get no duplicates and lose nothing.
  Expect ~2–3 messages/s; 20,000 messages takes about an hour or two.
- **iCloud only flags Sent and Trash** as special folders. The `folders:` map in
  `accounts.yaml` names Drafts, Junk and Archive.
- **Apple Mail and drafts:** drafts carry Apple's draft headers, so when you send one from
  Mail it replaces the draft instead of leaving a copy behind in Drafts.
- **claude.ai says "not connected" after a successful login:** fixed by forcing GitHub's
  account picker on every connect. Expect the picker; that's intentional.
- **A new tool doesn't appear in Claude:** tool lists are fetched per chat. Start a new
  chat. The log shows exactly what each client was offered.
- `fastmcp` is pinned on purpose: the GitHub allowlist hooks into a private attribute, and
  the server refuses to start if a newer fastmcp changes it.

---

## Setting this up with Claude Code

If you'd rather have Claude Code walk you through it, paste this into Claude Code on the Mac:

> Set up imap-mcp from https://github.com/g-maponus/imap-mcp on this Mac in remote (http)
> mode, following its README step by step. My iCloud address is `<you@icloud.com>`, my
> display name is `<Your Name>`, and my GitHub username is `<github-username>`. Rules: never ask
> me to paste a password, app-specific password, or OAuth client secret into this chat. For
> every secret, tell me to run `./set-secret.sh <name>` myself in a terminal (or with the `!`
> prefix). Do the steps you can do yourself (clone, venv, accounts.yaml, launchd plist, checks);
> tell me exactly what to click for the ones that need a browser (Apple app-specific password,
> Tailscale Funnel approval, GitHub OAuth App, claude.ai connector). Verify with `/health` and
> the log before telling me to add the connector.
