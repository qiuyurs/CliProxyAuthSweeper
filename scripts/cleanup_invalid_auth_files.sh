#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
CliProxyAuthSweeper (env-only mode)

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
  AUTO_INSTALL_JQ           Optional. 1|0 (default: 1)
  JQ_VERSION                Optional. Default: jq-1.7.1
  JQ_INSTALL_DIR            Optional. Default: $HOME/.local/bin (download fallback)

Examples:
  export MANAGEMENT_KEY='xxx'
  bash scripts/cleanup_invalid_auth_files.sh

  export RUN_MODE='observe'
  bash scripts/cleanup_invalid_auth_files.sh
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

to_bool01() {
  local raw="${1:-0}"
  local norm
  norm="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  case "$norm" in
    1|true|yes|y|on) echo 1 ;;
    *) echo 0 ;;
  esac
}

info() {
  printf '%s\n' "$*"
}

debug() {
  if [[ "$VERBOSE" -eq 1 ]]; then
    info "DEBUG: $*"
  fi
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

run_privileged() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
    return $?
  fi
  if command_exists sudo; then
    sudo "$@"
    return $?
  fi
  return 1
}

install_jq_via_pkg_manager() {
  if command_exists apt-get; then
    info "jq auto-install: trying apt-get"
    run_privileged env DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || return 1
    run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y jq >/dev/null 2>&1 || return 1
    return 0
  fi
  if command_exists dnf; then
    info "jq auto-install: trying dnf"
    run_privileged dnf install -y jq >/dev/null 2>&1 || return 1
    return 0
  fi
  if command_exists yum; then
    info "jq auto-install: trying yum"
    run_privileged yum install -y jq >/dev/null 2>&1 || return 1
    return 0
  fi
  if command_exists apk; then
    info "jq auto-install: trying apk"
    run_privileged apk add --no-cache jq >/dev/null 2>&1 || return 1
    return 0
  fi
  if command_exists pacman; then
    info "jq auto-install: trying pacman"
    run_privileged pacman -Sy --noconfirm jq >/dev/null 2>&1 || return 1
    return 0
  fi
  if command_exists zypper; then
    info "jq auto-install: trying zypper"
    run_privileged zypper --non-interactive install jq >/dev/null 2>&1 || return 1
    return 0
  fi
  if command_exists brew; then
    info "jq auto-install: trying brew"
    brew install jq >/dev/null 2>&1 || return 1
    return 0
  fi
  if command_exists choco; then
    info "jq auto-install: trying choco"
    choco install jq -y >/dev/null 2>&1 || return 1
    return 0
  fi
  if command_exists scoop; then
    info "jq auto-install: trying scoop"
    scoop install jq >/dev/null 2>&1 || return 1
    return 0
  fi
  return 1
}

install_jq_via_download() {
  local os arch asset url install_dir target

  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      debug "jq auto-install: unsupported arch for download fallback: $arch"
      return 1
      ;;
  esac

  case "$os" in
    linux*) asset="jq-linux-${arch}" ;;
    darwin*) asset="jq-macos-${arch}" ;;
    *)
      debug "jq auto-install: unsupported os for download fallback: $os"
      return 1
      ;;
  esac

  if [[ -n "$JQ_INSTALL_DIR" ]]; then
    install_dir="$JQ_INSTALL_DIR"
  else
    install_dir="${HOME:-/tmp}/.local/bin"
  fi
  target="${install_dir}/jq"
  url="https://github.com/jqlang/jq/releases/download/${JQ_VERSION}/${asset}"

  info "jq auto-install: downloading ${url}"
  mkdir -p "$install_dir" || return 1
  curl -fsSL -o "$target" "$url" || return 1
  chmod +x "$target" || return 1
  PATH="$install_dir:$PATH"
  export PATH
  return 0
}

ensure_jq() {
  if command_exists jq; then
    return 0
  fi

  if [[ "$AUTO_INSTALL_JQ" -ne 1 ]]; then
    die "jq not found and AUTO_INSTALL_JQ=0; please install jq manually"
  fi

  info "jq not found, starting auto-install"
  install_jq_via_pkg_manager || true
  if command_exists jq; then
    info "jq installed successfully via package manager"
    return 0
  fi

  install_jq_via_download || true
  if command_exists jq; then
    info "jq installed successfully via download fallback"
    return 0
  fi

  die "failed to auto-install jq; install jq manually and rerun"
}

BASE_URL="${BASE_URL:-http://localhost:8317/v0/management}"
MANAGEMENT_KEY="${MANAGEMENT_KEY:-}"
THRESHOLD="${THRESHOLD:-3}"
RUN_MODE="${RUN_MODE:-delete}"
LAST_RUN_EPOCH="${LAST_RUN_EPOCH:-}"
ALLOW_NAME_FALLBACK="$(to_bool01 "${ALLOW_NAME_FALLBACK:-1}")"
TIMEOUT="${TIMEOUT:-10}"
INSECURE="$(to_bool01 "${INSECURE:-0}")"
VERBOSE="$(to_bool01 "${VERBOSE:-0}")"
AUTO_INSTALL_JQ="$(to_bool01 "${AUTO_INSTALL_JQ:-1}")"
JQ_VERSION="${JQ_VERSION:-jq-1.7.1}"
JQ_INSTALL_DIR="${JQ_INSTALL_DIR:-}"

[[ -n "$MANAGEMENT_KEY" ]] || die "MANAGEMENT_KEY is required"
[[ "$THRESHOLD" =~ ^[0-9]+$ ]] || die "THRESHOLD must be an integer"
[[ "$THRESHOLD" -ge 1 ]] || die "THRESHOLD must be >= 1"
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "TIMEOUT must be an integer"
[[ "$TIMEOUT" -ge 1 ]] || die "TIMEOUT must be >= 1"
if [[ "$RUN_MODE" != "delete" && "$RUN_MODE" != "observe" ]]; then
  die "RUN_MODE must be one of: delete, observe"
fi
if [[ -n "$LAST_RUN_EPOCH" && ! "$LAST_RUN_EPOCH" =~ ^[0-9]+$ ]]; then
  die "LAST_RUN_EPOCH must be an integer epoch seconds"
fi

BASE_URL="${BASE_URL%/}"
RUN_STARTED_EPOCH="$(date -u +%s)"
RUN_STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

APPLY=1
if [[ "$RUN_MODE" == "observe" ]]; then
  APPLY=0
fi

require_cmd curl
ensure_jq

HTTP_BODY=""
HTTP_CODE=""
HTTP_CURL_RC=0

http_request_once() {
  local method="$1"
  local path="$2"
  local url="${BASE_URL}${path}"
  local -a curl_args
  local output=""

  curl_args=(
    -sS
    --connect-timeout "$TIMEOUT"
    --max-time "$TIMEOUT"
    -X "$method"
    -H "Accept: application/json"
    -H "Authorization: Bearer $MANAGEMENT_KEY"
    -H "X-Management-Key: $MANAGEMENT_KEY"
    -w $'\n__HTTP_CODE__:%{http_code}'
  )
  if [[ "$INSECURE" -eq 1 ]]; then
    curl_args+=(-k)
  fi

  set +e
  output="$(curl "${curl_args[@]}" "$url")"
  HTTP_CURL_RC=$?
  set -e

  if [[ $HTTP_CURL_RC -ne 0 ]]; then
    HTTP_BODY=""
    HTTP_CODE="000"
    return
  fi

  HTTP_CODE="${output##*$'\n'__HTTP_CODE__:}"
  HTTP_BODY="${output%$'\n'__HTTP_CODE__:*}"
}

http_request_with_retry() {
  local method="$1"
  local path="$2"
  local max_attempts=3
  local delay=1
  local attempt=1

  while (( attempt <= max_attempts )); do
    http_request_once "$method" "$path"
    debug "HTTP ${method} ${path} attempt=${attempt} rc=${HTTP_CURL_RC} code=${HTTP_CODE}"

    if [[ $HTTP_CURL_RC -eq 0 ]]; then
      if [[ "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then
        return 0
      fi
      if [[ "$HTTP_CODE" == "429" || "$HTTP_CODE" =~ ^5[0-9][0-9]$ ]]; then
        if (( attempt < max_attempts )); then
          sleep "$delay"
          delay=$((delay * 2))
          attempt=$((attempt + 1))
          continue
        fi
      fi
      return 0
    fi

    if (( attempt < max_attempts )); then
      sleep "$delay"
      delay=$((delay * 2))
      attempt=$((attempt + 1))
      continue
    fi
    return 1
  done
}

request_json_or_die() {
  local method="$1"
  local path="$2"
  http_request_with_retry "$method" "$path" || die "${method} ${path} network failure after retries"
  [[ "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]] || die "${method} ${path} failed with HTTP ${HTTP_CODE}; body=${HTTP_BODY}"
  jq -e . >/dev/null 2>&1 <<<"$HTTP_BODY" || die "${method} ${path} returned invalid JSON"
}

build_usage_analysis() {
  local usage_json="$1"
  local last_epoch_json="null"
  if [[ -n "$LAST_RUN_EPOCH" ]]; then
    last_epoch_json="$LAST_RUN_EPOCH"
  fi

  jq \
    --argjson threshold "$THRESHOLD" \
    --argjson now_epoch "$RUN_STARTED_EPOCH" \
    --argjson last_epoch "$last_epoch_json" \
    '
    def flatten_events:
      [
        (.usage.apis? // {} | to_entries[]? | .value.models? // {} | to_entries[]? | .value.details? // [] | .[]?)
        | select(.timestamp? and .auth_index?)
        | {
            timestamp: (.timestamp | tostring),
            auth_index: (.auth_index | tostring),
            failed: ((.failed // false) | if type == "boolean" then . else false end)
          }
      ];

    def parse_epoch:
      (.timestamp | sub("\\.[0-9]+"; "") | fromdateiso8601?) // null;

    def in_window($last; $now):
      if $last == null then
        (.epoch <= $now)
      else
        (.epoch > $last and .epoch <= $now)
      end;

    def calc_streaks($events):
      reduce $events[] as $e
      ({};
        .[$e.auth_index] = (
          .[$e.auth_index] // {
            current_streak: 0,
            max_streak: 0,
            last_timestamp: null,
            last_failed: null
          }
          | if $e.failed then .current_streak = (.current_streak + 1) else .current_streak = 0 end
          | .max_streak = (if .current_streak > .max_streak then .current_streak else .max_streak end)
          | .last_timestamp = $e.timestamp
          | .last_failed = $e.failed
        )
      );

    (flatten_events | map(. + {epoch: parse_epoch}) | map(select(.epoch != null))) as $all_events
    | ($all_events | map(select(in_window($last_epoch; $now_epoch))) | sort_by(.epoch)) as $window_events
    | (calc_streaks($window_events)) as $streak_map
    | {
        usage_total_events: ($all_events | length),
        usage_window_events: ($window_events | length),
        window_mode: (if $last_epoch == null then "full" else "incremental" end),
        bad_auth_indexes: (
          $streak_map
          | to_entries
          | map({
              auth_index: .key,
              max_streak: .value.max_streak,
              last_timestamp: .value.last_timestamp,
              last_failed: .value.last_failed
            })
          | map(select(.max_streak >= $threshold))
          | sort_by(.auth_index)
        )
      }
    ' <<<"$usage_json"
}

build_candidates() {
  local analysis_json="$1"
  local auth_files_json="$2"
  jq -s \
    --argjson allow_name_fallback "$ALLOW_NAME_FALLBACK" \
    '
    def normalize_name: sub("\\.json$"; "");

    def find_by_id($files; $idx):
      $files | map(select((.id? != null) and ((.id | tostring) == $idx)));

    def find_by_name($files; $idx):
      $files | map(
        select(
          ((.name // "") == $idx)
          or (((.name // "") | normalize_name) == $idx)
        )
      );

    def pick_matches($files; $idx; $fallback):
      (find_by_id($files; $idx)) as $id_matches
      | if ($id_matches | length) > 0 then
          {match_mode: "id", matches: $id_matches}
        elif $fallback == 1 then
          (find_by_name($files; $idx)) as $name_matches
          | {match_mode: "name_fallback", matches: $name_matches}
        else
          {match_mode: "none", matches: []}
        end;

    (.[0].bad_auth_indexes // []) as $bad
    | (.[1].files // []) as $files
    | reduce $bad[] as $b (
        {candidates: [], skipped: []};
        (pick_matches($files; $b.auth_index; $allow_name_fallback)) as $picked
        | if ($picked.matches | length) == 0 then
            .skipped += [{auth_index: $b.auth_index, reason: "unmatched"}]
          elif ($picked.matches | length) > 1 then
            .skipped += [{
              auth_index: $b.auth_index,
              reason: "ambiguous_match",
              match_count: ($picked.matches | length)
            }]
          else
            ($picked.matches[0]) as $f
            | if (($f.source // "") != "file") then
                .skipped += [{
                  auth_index: $b.auth_index,
                  file_name: ($f.name // ""),
                  reason: "source_not_file"
                }]
              elif (($f.runtime_only // false) == true) then
                .skipped += [{
                  auth_index: $b.auth_index,
                  file_name: ($f.name // ""),
                  reason: "runtime_only"
                }]
              elif ((($f.name // "") | endswith(".json")) | not) then
                .skipped += [{
                  auth_index: $b.auth_index,
                  file_name: ($f.name // ""),
                  reason: "not_json"
                }]
              else
                .candidates += [{
                  auth_index: $b.auth_index,
                  file_name: ($f.name // ""),
                  file_id: ($f.id // null),
                  match_mode: $picked.match_mode,
                  max_streak: $b.max_streak,
                  last_timestamp: $b.last_timestamp
                }]
              end
          end
      )
    | .candidates |= (sort_by(.file_name) | unique_by(.file_name))
    ' <(printf '%s' "$analysis_json") <(printf '%s' "$auth_files_json")
}

lines_to_json_array() {
  local -n ref="$1"
  if [[ "${#ref[@]}" -eq 0 ]]; then
    echo "[]"
    return
  fi
  printf '%s\n' "${ref[@]}" | jq -sc '.'
}

info "run_started_at=${RUN_STARTED_AT}"
info "run_mode=${RUN_MODE} (default is delete)"
if [[ -n "$LAST_RUN_EPOCH" ]]; then
  info "window=incremental from_epoch=${LAST_RUN_EPOCH} to_epoch=${RUN_STARTED_EPOCH}"
else
  info "window=full (LAST_RUN_EPOCH not set)"
fi

request_json_or_die GET "/usage"
usage_json="$HTTP_BODY"
analysis_json="$(build_usage_analysis "$usage_json")"

request_json_or_die GET "/auth-files"
auth_files_json="$HTTP_BODY"
match_json="$(build_candidates "$analysis_json" "$auth_files_json")"

usage_total_events="$(jq -r '.usage_total_events' <<<"$analysis_json")"
usage_window_events="$(jq -r '.usage_window_events' <<<"$analysis_json")"
window_mode="$(jq -r '.window_mode' <<<"$analysis_json")"
bad_count="$(jq -r '.bad_auth_indexes | length' <<<"$analysis_json")"
candidate_count="$(jq -r '.candidates | length' <<<"$match_json")"
skipped_count="$(jq -r '.skipped | length' <<<"$match_json")"

info "usage_total_events=${usage_total_events} usage_window_events=${usage_window_events} window_mode=${window_mode}"
info "bad_auth_indexes=${bad_count} delete_candidates=${candidate_count} skipped=${skipped_count}"

if [[ "$candidate_count" -gt 0 ]]; then
  info "candidates:"
  jq -r '.candidates[] | "- \(.file_name) (auth_index=\(.auth_index), max_streak=\(.max_streak), match=\(.match_mode))"' <<<"$match_json"
fi

declare -a deleted_lines
declare -a error_lines
deleted_lines=()
error_lines=()

if [[ "$APPLY" -eq 1 ]]; then
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    file_name="$(jq -r '.file_name' <<<"$candidate")"
    encoded_name="$(jq -rn --arg v "$file_name" '$v|@uri')"
    path="/auth-files?name=${encoded_name}"

    http_request_with_retry DELETE "$path" || true
    if [[ "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then
      deleted_lines+=("$(jq -nc --arg file_name "$file_name" --arg code "$HTTP_CODE" '{file_name:$file_name,http_code:($code|tonumber)}')")
    else
      error_lines+=("$(jq -nc --arg file_name "$file_name" --arg code "$HTTP_CODE" --arg body "$HTTP_BODY" '{file_name:$file_name,http_code:$code,response_body:$body}')")
    fi
  done < <(jq -c '.candidates[]' <<<"$match_json")
else
  info "observe mode: no deletion executed"
fi

deleted_json="$(lines_to_json_array deleted_lines)"
errors_json="$(lines_to_json_array error_lines)"
deleted_count="$(jq -r 'length' <<<"$deleted_json")"
error_count="$(jq -r 'length' <<<"$errors_json")"

if [[ "$APPLY" -eq 1 ]]; then
  info "delete_result: deleted=${deleted_count} failed=${error_count}"
fi

report_json="$(jq -n \
  --arg run_started_at "$RUN_STARTED_AT" \
  --argjson run_started_epoch "$RUN_STARTED_EPOCH" \
  --arg run_mode "$RUN_MODE" \
  --argjson threshold "$THRESHOLD" \
  --arg base_url "$BASE_URL" \
  --argjson allow_name_fallback "$ALLOW_NAME_FALLBACK" \
  --arg last_run_epoch "$LAST_RUN_EPOCH" \
  --argjson analysis "$analysis_json" \
  --argjson match "$match_json" \
  --argjson deleted "$deleted_json" \
  --argjson errors "$errors_json" \
  '{
    run_started_at: $run_started_at,
    run_started_epoch: $run_started_epoch,
    run_mode: $run_mode,
    threshold: $threshold,
    base_url: $base_url,
    allow_name_fallback: ($allow_name_fallback == 1),
    last_run_epoch_input: (if $last_run_epoch == "" then null else ($last_run_epoch | tonumber) end),
    next_last_run_epoch: $run_started_epoch,
    next_last_run_at: $run_started_at,
    window_mode: ($analysis.window_mode // "unknown"),
    usage_total_events: ($analysis.usage_total_events // 0),
    usage_window_events: ($analysis.usage_window_events // 0),
    bad_auth_indexes: ($analysis.bad_auth_indexes // []),
    delete_candidates: ($match.candidates // []),
    skipped: ($match.skipped // []),
    deleted: $deleted,
    errors: $errors
  }')"

info "NEXT_LAST_RUN_EPOCH=${RUN_STARTED_EPOCH}"
info "NEXT_LAST_RUN_AT=${RUN_STARTED_AT}"
if [[ "$VERBOSE" -eq 1 ]]; then
  info "report_json=${report_json}"
fi

if [[ "$APPLY" -eq 1 && "$error_count" -gt 0 ]]; then
  exit 2
fi
