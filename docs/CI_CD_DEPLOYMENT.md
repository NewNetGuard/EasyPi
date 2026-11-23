# CI/CD deployment

EasyPi uses two separate GitHub Actions gates:

- `.github/workflows/ci.yml` tests the backend, frontend, shell scripts, release tooling, and Chameleon on every push and pull request.
- `.github/workflows/deploy-release.yml` manually deploys one already published and signed release through Tailscale.

The deployment job never receives the EasyPi release signing key. The target downloads the archive and detached signature from GitHub, then the existing root-owned updater verifies them against the public key already installed on EasyPi. The updater snapshots the current application and database, checks runtime health, and rolls back a failed update.

## One-time GitHub setup

Create a GitHub environment named `production` and add a required reviewer. Add these environment secrets:

| Secret | Value |
| --- | --- |
| `TS_OAUTH_CLIENT_ID` | Tailscale OAuth client ID with writable `auth_keys` scope and permission to create `tag:ci` nodes |
| `TS_OAUTH_SECRET` | Matching Tailscale OAuth secret |
| `EASYPI_DEPLOY_HOST` | EasyPi's Tailscale DNS name, without a username or URL scheme |
| `EASYPI_DEPLOY_USER` | Restricted Linux deployment account |
| `EASYPI_DEPLOY_SSH_KEY` | Private SSH key for that deployment account |
| `EASYPI_DEPLOY_KNOWN_HOSTS` | Independently verified OpenSSH host-key line for `EASYPI_DEPLOY_HOST` |

Keep EasyPi owned by the personal Tailscale account so Taildrop remains available. Give `tag:ci` TCP port 22 access only to this EasyPi node in the tailnet policy. Do not grant the CI tag general access to the LAN.

The deployment account needs non-interactive sudo permission only for the signed updater. The updater still rejects an unsigned or modified archive:

```text
easypi-deploy ALL=(root) NOPASSWD: /opt/EasyPi/scripts/maintenance/apply_update.sh *
```

Verify the SSH host-key fingerprint directly on EasyPi before saving `EASYPI_DEPLOY_KNOWN_HOSTS`. Do not create it with an unattended `ssh-keyscan` inside the workflow, because that would trust whichever host answered first.

## Deploy

Open **Actions → Deploy signed release → Run workflow**, enter a release tag such as `v1.1.1`, and approve the `production` environment deployment. The job:

1. validates the tag and target;
2. joins the tailnet as an ephemeral `tag:ci` node;
3. downloads the immutable release assets and checks `SHA256SUMS.txt`;
4. connects with strict SSH host-key checking;
5. runs the signed updater with rollback and health checks;
6. confirms the installed version and `/health` response.

Only published signed releases can pass the target's trust check. A source branch or pull request is never copied directly to the production EasyPi.

