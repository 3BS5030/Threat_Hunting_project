#!/usr/bin/env bash
# export_logs.sh - Export target Linux logs for offline threat hunting analysis
# Runs as a regular user with sudo privileges on lab VMs (CentOS, Debian, Ubuntu).
# Read-only execution: does NOT modify any log files or system configuration.
# Makes ZERO network calls.

set -euo pipefail

OUT_DIR="${1:-./exported_logs}"
mkdir -p "$OUT_DIR"

echo "=== VM Threat Hunting Log Exporter ==="
echo "Exporting to: $OUT_DIR"
echo "Host: $(hostname -f 2>/dev/null || hostname)"
echo "Time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Safe helper to tail up to 20000 lines trying standard user permissions first,
# then falling back to non-interactive sudo (sudo -n).
read_log_file() {
    local src="$1"
    local dst="$2"

    if [ ! -e "$src" ]; then
        return 1
    fi

    echo "  [+] Reading $src -> $(basename "$dst")"
    if tail -n 20000 "$src" >> "$dst" 2>/dev/null; then
        return 0
    elif sudo -n /usr/bin/tail -n 20000 "$src" >> "$dst" 2>/dev/null; then
        return 0
    elif sudo -n tail -n 20000 "$src" >> "$dst" 2>/dev/null; then
        return 0
    else
        echo "  [!] Permission denied reading $src (even with sudo -n)"
        return 2
    fi
}

# 1. os-release
if [ -f /etc/os-release ]; then
    cp /etc/os-release "$OUT_DIR/os-release.txt"
    echo "  [+] Copied /etc/os-release -> os-release.txt"
fi

# 2. Authentication logs (auth.log)
> "$OUT_DIR/auth.log"
read_log_file "/var/log/secure" "$OUT_DIR/auth.log" || \
read_log_file "/var/log/auth.log" "$OUT_DIR/auth.log" || true

# 3. System messages (syslog.log)
> "$OUT_DIR/syslog.log"
read_log_file "/var/log/messages" "$OUT_DIR/syslog.log" || \
read_log_file "/var/log/syslog" "$OUT_DIR/syslog.log" || true

# 4. Audit logs (audit.log)
> "$OUT_DIR/audit.log"
read_log_file "/var/log/audit/audit.log" "$OUT_DIR/audit.log" || true

# 5. Cron logs (cron.log)
> "$OUT_DIR/cron.log"
read_log_file "/var/log/cron" "$OUT_DIR/cron.log" || \
read_log_file "/var/log/cron.log" "$OUT_DIR/cron.log" || true

# 6. Package logs (package.log) - concatenate all available package manager logs
> "$OUT_DIR/package.log"
read_log_file "/var/log/yum.log" "$OUT_DIR/package.log" || true
read_log_file "/var/log/dnf.rpm.log" "$OUT_DIR/package.log" || true
read_log_file "/var/log/dpkg.log" "$OUT_DIR/package.log" || true

# 7. Web server access & error logs
> "$OUT_DIR/web_access.log"
read_log_file "/var/log/httpd/access_log" "$OUT_DIR/web_access.log" || \
read_log_file "/var/log/apache2/access.log" "$OUT_DIR/web_access.log" || \
read_log_file "/var/log/nginx/access.log" "$OUT_DIR/web_access.log" || true

> "$OUT_DIR/web_error.log"
read_log_file "/var/log/httpd/error_log" "$OUT_DIR/web_error.log" || \
read_log_file "/var/log/apache2/error.log" "$OUT_DIR/web_error.log" || \
read_log_file "/var/log/nginx/error.log" "$OUT_DIR/web_error.log" || true

# 8. Connecting user's bash history
HIST_FILE="${HOME}/.bash_history"
if [ -f "$HIST_FILE" ]; then
    tail -n 20000 "$HIST_FILE" > "$OUT_DIR/history.log" 2>/dev/null || true
    echo "  [+] Exported $HIST_FILE -> history.log"
else
    > "$OUT_DIR/history.log"
fi

echo "=== Export Complete. Logs written to $OUT_DIR ==="
ls -lh "$OUT_DIR"
