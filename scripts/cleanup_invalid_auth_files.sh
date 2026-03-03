#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
CliProxyAuthSweeper (env-only mode, no jq required)

Environment variables:
  MANAGEMENT_KEY            Required. Management API key.
  BASE_URL                  Optional. Default: http://localhost:8317/v0/management
  THRESHOLD                 Optional. Default: 3
  RUN_MODE                  Optional. delete|observe (default: delete)
  LAST_RUN_EPOCH            Optional. If set, only analyze (LAST_RUN_EPOCH, now]
  ALLOW_NAME_FALLBACK       Optional. 1|0 (default: 1)
  TIMEOUT                   Optional. HTTP timeout seconds (default: 10)
  INSECURE                  Optional. 1|0 (default: 0)
  VERBOSE                   Optional. 1|0 (default: 0)
  PYTHON_BIN                Optional. Default: python3 (fallback: python)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -gt 0 ]]; then
  echo "ERROR: this script accepts environment variables only; remove CLI arguments" >&2
  exit 1
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "ERROR: python is required (python3 or python not found)" >&2
    exit 1
  fi
fi

exec "$PYTHON_BIN" - <<'PY'
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def to_bool(v, default=False):
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def info(msg):
    print(msg)


def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def parse_int(name, raw, min_value=None, required=False):
    if raw is None or raw == "":
        if required:
            die(f"{name} is required")
        return None
    try:
        value = int(str(raw))
    except Exception:
        die(f"{name} must be an integer")
    if min_value is not None and value < min_value:
        die(f"{name} must be >= {min_value}")
    return value


def parse_timestamp_to_epoch(ts):
    if not isinstance(ts, str):
        return None
    s = ts.strip()
    if not s:
        return None

    # Normalize RFC3339/ISO8601 variants safely.
    m = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$",
        s,
    )
    if not m:
        return None

    base, frac, tz = m.group(1), m.group(2), m.group(3)
    if frac:
        frac = frac[:6]
        norm = f"{base}.{frac}"
    else:
        norm = base

    if tz is None or tz == "Z":
        tz = "+00:00"
    norm = f"{norm}{tz}"

    try:
        dt = datetime.fromisoformat(norm)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def http_request_with_retry(base_url, path, method, headers, timeout, insecure):
    max_attempts = 3
    delay = 1
    context = ssl._create_unverified_context() if insecure else None
    url = f"{base_url}{path}"

    for attempt in range(1, max_attempts + 1):
        req = urllib.request.Request(url=url, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                code = resp.getcode()
                body = resp.read().decode("utf-8", errors="replace")
                return code, body
        except urllib.error.HTTPError as e:
            code = int(getattr(e, "code", 0) or 0)
            body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
            if (code == 429 or 500 <= code <= 599) and attempt < max_attempts:
                time.sleep(delay)
                delay *= 2
                continue
            return code, body
        except Exception:
            if attempt < max_attempts:
                time.sleep(delay)
                delay *= 2
                continue
            return 0, ""

    return 0, ""


def request_json_or_die(base_url, path, method, headers, timeout, insecure):
    code, body = http_request_with_retry(
        base_url=base_url,
        path=path,
        method=method,
        headers=headers,
        timeout=timeout,
        insecure=insecure,
    )
    if not (200 <= code < 300):
        die(f"{method} {path} failed with HTTP {code}; body={body}")
    try:
        return json.loads(body)
    except Exception:
        die(f"{method} {path} returned invalid JSON")


def build_usage_analysis(usage_obj, threshold, run_started_epoch, last_run_epoch):
    events = []
    usage = usage_obj.get("usage", {}) if isinstance(usage_obj, dict) else {}
    apis = usage.get("apis", {}) if isinstance(usage, dict) else {}
    if isinstance(apis, dict):
        for _, api_data in apis.items():
            models = api_data.get("models", {}) if isinstance(api_data, dict) else {}
            if not isinstance(models, dict):
                continue
            for _, model_data in models.items():
                details = model_data.get("details", []) if isinstance(model_data, dict) else []
                if not isinstance(details, list):
                    continue
                for d in details:
                    if not isinstance(d, dict):
                        continue
                    if "timestamp" not in d or "auth_index" not in d:
                        continue
                    epoch = parse_timestamp_to_epoch(str(d.get("timestamp")))
                    if epoch is None:
                        continue
                    failed = d.get("failed", False)
                    if not isinstance(failed, bool):
                        failed = False
                    events.append(
                        {
                            "timestamp": str(d.get("timestamp")),
                            "epoch": epoch,
                            "auth_index": str(d.get("auth_index")),
                            "failed": failed,
                        }
                    )

    if last_run_epoch is None:
        window_events = [e for e in events if e["epoch"] <= run_started_epoch]
        window_mode = "full"
    else:
        window_events = [
            e for e in events if last_run_epoch < e["epoch"] <= run_started_epoch
        ]
        window_mode = "incremental"

    window_events.sort(key=lambda x: x["epoch"])

    streaks = {}
    for e in window_events:
        idx = e["auth_index"]
        state = streaks.setdefault(
            idx,
            {
                "current_streak": 0,
                "max_streak": 0,
                "last_timestamp": None,
                "last_failed": None,
            },
        )
        if e["failed"]:
            state["current_streak"] += 1
        else:
            state["current_streak"] = 0
        if state["current_streak"] > state["max_streak"]:
            state["max_streak"] = state["current_streak"]
        state["last_timestamp"] = e["timestamp"]
        state["last_failed"] = e["failed"]

    bad_auth_indexes = []
    for auth_index, st in streaks.items():
        if st["max_streak"] >= threshold:
            bad_auth_indexes.append(
                {
                    "auth_index": auth_index,
                    "max_streak": st["max_streak"],
                    "last_timestamp": st["last_timestamp"],
                    "last_failed": st["last_failed"],
                }
            )
    bad_auth_indexes.sort(key=lambda x: x["auth_index"])

    return {
        "usage_total_events": len(events),
        "usage_window_events": len(window_events),
        "window_mode": window_mode,
        "bad_auth_indexes": bad_auth_indexes,
    }


def build_candidates(analysis, auth_files_obj, allow_name_fallback):
    files = auth_files_obj.get("files", []) if isinstance(auth_files_obj, dict) else []
    if not isinstance(files, list):
        files = []
    bad = analysis.get("bad_auth_indexes", [])
    if not isinstance(bad, list):
        bad = []

    def normalize_name(name):
        s = str(name or "")
        return s[:-5] if s.endswith(".json") else s

    def find_by_id(idx):
        return [f for f in files if isinstance(f, dict) and str(f.get("id")) == idx]

    def find_by_name(idx):
        out = []
        for f in files:
            if not isinstance(f, dict):
                continue
            name = str(f.get("name", ""))
            if name == idx or normalize_name(name) == idx:
                out.append(f)
        return out

    candidates = []
    skipped = []
    for b in bad:
        idx = str(b.get("auth_index", ""))
        id_matches = find_by_id(idx)
        match_mode = "id"
        matches = id_matches

        if not matches and allow_name_fallback:
            matches = find_by_name(idx)
            match_mode = "name_fallback"

        if not matches:
            skipped.append({"auth_index": idx, "reason": "unmatched"})
            continue

        if len(matches) > 1:
            skipped.append(
                {
                    "auth_index": idx,
                    "reason": "ambiguous_match",
                    "match_count": len(matches),
                }
            )
            continue

        f = matches[0]
        file_name = str(f.get("name", ""))
        if str(f.get("source", "")) != "file":
            skipped.append(
                {"auth_index": idx, "file_name": file_name, "reason": "source_not_file"}
            )
            continue
        if bool(f.get("runtime_only", False)) is True:
            skipped.append(
                {"auth_index": idx, "file_name": file_name, "reason": "runtime_only"}
            )
            continue
        if not file_name.endswith(".json"):
            skipped.append({"auth_index": idx, "file_name": file_name, "reason": "not_json"})
            continue

        candidates.append(
            {
                "auth_index": idx,
                "file_name": file_name,
                "file_id": f.get("id"),
                "match_mode": match_mode,
                "max_streak": b.get("max_streak"),
                "last_timestamp": b.get("last_timestamp"),
            }
        )

    # unique by file_name
    seen = set()
    uniq = []
    for c in sorted(candidates, key=lambda x: x["file_name"]):
        fn = c["file_name"]
        if fn in seen:
            continue
        seen.add(fn)
        uniq.append(c)

    return {"candidates": uniq, "skipped": skipped}


def main():
    management_key = os.getenv("MANAGEMENT_KEY", "").strip()
    if not management_key:
        die("MANAGEMENT_KEY is required")

    base_url = os.getenv("BASE_URL", "http://localhost:8317/v0/management").rstrip("/")
    threshold = parse_int("THRESHOLD", os.getenv("THRESHOLD", "3"), min_value=1, required=True)
    run_mode = os.getenv("RUN_MODE", "delete").strip().lower()
    if run_mode not in {"delete", "observe"}:
        die("RUN_MODE must be one of: delete, observe")
    last_run_epoch = parse_int("LAST_RUN_EPOCH", os.getenv("LAST_RUN_EPOCH"), min_value=0, required=False)
    allow_name_fallback = to_bool(os.getenv("ALLOW_NAME_FALLBACK", "1"), default=True)
    timeout = parse_int("TIMEOUT", os.getenv("TIMEOUT", "10"), min_value=1, required=True)
    insecure = to_bool(os.getenv("INSECURE", "0"), default=False)
    verbose = to_bool(os.getenv("VERBOSE", "0"), default=False)

    apply_mode = run_mode == "delete"
    run_started_epoch = int(time.time())
    run_started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    info(f"run_started_at={run_started_at}")
    info(f"run_mode={run_mode} (default is delete)")
    if last_run_epoch is None:
        info("window=full (LAST_RUN_EPOCH not set)")
    else:
        info(f"window=incremental from_epoch={last_run_epoch} to_epoch={run_started_epoch}")

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {management_key}",
        "X-Management-Key": management_key,
    }

    usage_obj = request_json_or_die(
        base_url=base_url,
        path="/usage",
        method="GET",
        headers=headers,
        timeout=timeout,
        insecure=insecure,
    )
    analysis = build_usage_analysis(
        usage_obj=usage_obj,
        threshold=threshold,
        run_started_epoch=run_started_epoch,
        last_run_epoch=last_run_epoch,
    )

    auth_files_obj = request_json_or_die(
        base_url=base_url,
        path="/auth-files",
        method="GET",
        headers=headers,
        timeout=timeout,
        insecure=insecure,
    )
    match = build_candidates(
        analysis=analysis,
        auth_files_obj=auth_files_obj,
        allow_name_fallback=allow_name_fallback,
    )

    usage_total_events = int(analysis.get("usage_total_events", 0))
    usage_window_events = int(analysis.get("usage_window_events", 0))
    window_mode = analysis.get("window_mode", "unknown")
    bad_count = len(analysis.get("bad_auth_indexes", []))
    candidate_count = len(match.get("candidates", []))
    skipped_count = len(match.get("skipped", []))

    info(
        f"usage_total_events={usage_total_events} "
        f"usage_window_events={usage_window_events} window_mode={window_mode}"
    )
    info(
        f"bad_auth_indexes={bad_count} delete_candidates={candidate_count} skipped={skipped_count}"
    )

    if candidate_count > 0:
        info("candidates:")
        for c in match["candidates"]:
            info(
                f"- {c['file_name']} "
                f"(auth_index={c['auth_index']}, max_streak={c['max_streak']}, match={c['match_mode']})"
            )

    deleted = []
    errors = []
    if apply_mode:
        for c in match.get("candidates", []):
            file_name = c["file_name"]
            encoded_name = urllib.parse.quote(file_name, safe="")
            code, body = http_request_with_retry(
                base_url=base_url,
                path=f"/auth-files?name={encoded_name}",
                method="DELETE",
                headers=headers,
                timeout=timeout,
                insecure=insecure,
            )
            if 200 <= code < 300:
                deleted.append({"file_name": file_name, "http_code": code})
            else:
                errors.append(
                    {"file_name": file_name, "http_code": code, "response_body": body}
                )
        info(f"delete_result: deleted={len(deleted)} failed={len(errors)}")
    else:
        info("observe mode: no deletion executed")

    report = {
        "run_started_at": run_started_at,
        "run_started_epoch": run_started_epoch,
        "run_mode": run_mode,
        "threshold": threshold,
        "base_url": base_url,
        "allow_name_fallback": allow_name_fallback,
        "last_run_epoch_input": last_run_epoch,
        "next_last_run_epoch": run_started_epoch,
        "next_last_run_at": run_started_at,
        "window_mode": window_mode,
        "usage_total_events": usage_total_events,
        "usage_window_events": usage_window_events,
        "bad_auth_indexes": analysis.get("bad_auth_indexes", []),
        "delete_candidates": match.get("candidates", []),
        "skipped": match.get("skipped", []),
        "deleted": deleted,
        "errors": errors,
    }

    info(f"NEXT_LAST_RUN_EPOCH={run_started_epoch}")
    info(f"NEXT_LAST_RUN_AT={run_started_at}")
    if verbose:
        info("report_json=" + json.dumps(report, ensure_ascii=False, separators=(",", ":")))

    if apply_mode and errors:
        sys.exit(2)


if __name__ == "__main__":
    main()
PY
