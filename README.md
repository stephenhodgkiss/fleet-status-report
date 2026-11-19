# fleet-status-report

A single, read-only bash script that audits the real-world security posture of an Ubuntu LAMP server. Run it before and after reboots, before hardening, or on any inherited box. It changes nothing and prints no secret values.

```bash
curl -fsSL https://raw.githubusercontent.com/stephenhodgkiss/fleet-status-report/main/fleet-status-report.sh -o fleet-status-report.sh
sudo bash fleet-status-report.sh
```

## Why this exists

Most server audit scripts check the obvious things: firewall rules, pending updates, sshd settings. This one also checks the failure modes that actually caused real outages on a real production fleet, the kind that are invisible in config files and only surface at 2am after a reboot:

- **A service that is running but disabled vanishes on the next reboot.** A redis instance restarted by hand months earlier, never enabled, silently died on reboot and took a PHP site down mid-page-render.
- **A service that is stopped but enabled APPEARS on the next reboot.** An nginx package installed long ago, stopped by hand, never disabled, started at boot, stole port 80 from Apache. Total outage.
- **ufw's `/etc/ufw/sysctl.conf` silently reverts kernel hardening.** ufw starts after systemd-sysctl and applies its own values, so `log_martians = 1` set via a sysctl.d drop-in verifies green, then reverts to 0 on every boot. The config file and `sysctl --system` both look correct while the runtime value is wrong.
- **Config files lie about MySQL and Redis binds.** On Ubuntu, the MySQL include chain means a `bind-address` in `mysql.conf.d/` may never be parsed. The only truth is what the running daemon is actually listening on, which is what this script reports.
- **Webroots collect `.env`, `.log`, `.sql` and `.bak` files** that become live URLs. The script inventories them (permissions only, no contents) so you can block them before someone else finds them.

## What it checks

| Section | What it covers |
|---|---|
| Host | OS, kernel, uptime, pending reboot |
| SSH | Effective `sshd -T` values (not the config file), drop-in order for first-match-wins conflicts |
| Firewall | UFW rules with default policy, or raw iptables if UFW is absent |
| Listening ports | Every listener with owning process, to spot DB/cache services on public binds |
| Rival web servers | nginx/lighttpd/caddy packages installed on an Apache box, the port-80 steal scenario |
| Apache | Effective banner settings, PHP `expose_php` per SAPI, sensitive-file block conf, docroots |
| Webroot files | `.env`, logs, SQL dumps, backups: permissions and paths, no contents |
| Sysctl | Redirects, martians, syncookies, source routing, plus the ufw sysctl clobber check |
| MySQL / Redis | Running-daemon bind addresses, not config files |
| Services | `is-enabled` AND `is-active` side by side, both reboot landmine directions |
| fail2ban | Status, bans, ignoreip hygiene |
| Updates | Pending count and list, unattended-upgrades stack blacklist presence |
| Docker | Published ports and DNAT rules (Docker bypasses UFW) |
| TLS | Certificate expiry and subjects for all vhosts |
| Resources | Disk, memory, load |

## Scope and safety

- Targets Ubuntu 22.04/24.04 LAMP servers. Nothing is Ubuntu-specific enough to break elsewhere, but that is what it is tested on.
- Strictly read-only. The only file it writes is a temp list of pending updates, removed immediately.
- Prints no secrets: file listings show permissions and names only, never contents.
- Requires root (or sudo) for full output: `sshd -T`, `ss -p`, UFW, fail2ban-client and MySQL socket auth all need it.

## Running it across a fleet

The output is plain text with `=====` section markers, so it diffs well. Two patterns that work at fleet scale:

1. **Pre/post reboot diff**: save `ss -tlnp` output before a reboot and diff after. Any service that appears or disappears is a finding.
2. **Paste-back operation**: for servers where you have no SSH route, hand the script to whoever can run it and analyze the pasted output remotely. It is self-contained with no dependencies beyond coreutils and the services it inspects.

## License

MIT
