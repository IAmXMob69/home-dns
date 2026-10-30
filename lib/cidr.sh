# Strict IP prefix validation for the firewall tools: the Bash mirror of
# go/internal/cidr (the policy is written there). Both must accept and
# reject the same lines; tests/fixtures/cidr-cases.tsv is run through both.
#   cidr_valid v4|v6 LINE    print LINE trimmed, or fail with the reason on stderr
#   cidr_filter v4|v6 < in   print the valid prefixes, skipping blank and # lines;
#                            fail (print nothing) on the first invalid line
# Uses glob matching rather than =~ in the hot path: bash recompiles a regex
# on every test, which made a 30k-line country list take ~13 s.
# shellcheck shell=bash

_cidr_ws=$' \t\r\n\v\f'

# _cidr_bad REASON: uses the caller's $s and $fam (dynamic scope).
_cidr_bad() { _cidr_err="\"$s\" is not a valid ${fam/v/IPv} prefix: $1"; return 1; }

# _cidr_num STR MAX: decimal, no leading zeros, at most 3 digits, <= MAX.
_cidr_num() {
  case "$1" in
    [0-9] | [1-9][0-9] | [1-9][0-9][0-9]) (( 10#$1 <= $2 )) ;;
    *) return 1 ;;
  esac
}

# _cidr_hex STR: 1-4 hex digits.
_cidr_hex() {
  case "$1" in
    "" | ?????* | *[!0-9A-Fa-f]*) return 1 ;;
  esac
}

# _cidr_check v4|v6 LINE: set _cidr_out (trimmed prefix) or _cidr_err.
_cidr_check() {
  local fam="$1" s="$2" addr bits max=32 i v left right
  local -a g l r
  _cidr_out="" _cidr_err=""
  s="${s#"${s%%[!"${_cidr_ws}"]*}"}"
  s="${s%"${s##*[!"${_cidr_ws}"]}"}"
  [[ "$s" == */* ]] || { _cidr_bad "missing /length"; return; }
  addr="${s%%/*}" bits="${s#*/}"
  [[ "$fam" == v6 ]] && max=128
  _cidr_num "$bits" "$max" || { _cidr_bad "length must be 1-$max without leading zeros"; return; }
  (( 10#$bits > 0 )) || { _cidr_bad "/0 would match every address"; return; }
  if [[ "$fam" == v4 ]]; then
    [[ "$addr" != *[!0-9.]* ]] || { _cidr_bad "unexpected character"; return; }
    [[ "$addr" == *.*.*.* && "$addr" != *.*.*.*.* ]] || { _cidr_bad "bad address"; return; }
    g=("${addr%%.*}") addr="${addr#*.}"
    g+=("${addr%%.*}") addr="${addr#*.}"
    g+=("${addr%%.*}" "${addr#*.}")
    v=0
    for i in "${g[@]}"; do
      case "$i" in
        [0-9] | [1-9][0-9] | 1[0-9][0-9] | 2[0-4][0-9] | 25[0-5]) v=$(( (v << 8) | 10#$i )) ;;
        *) _cidr_bad "bad address"; return ;;
      esac
    done
    (( (v & ((1 << (32 - 10#$bits)) - 1)) == 0 )) || { _cidr_bad "host bits set"; return; }
  else
    [[ "$addr" != *[!0-9A-Fa-f:]* ]] || { _cidr_bad "unexpected character"; return; }
    if [[ "$addr" == *::* ]]; then
      left="${addr%%::*}" right="${addr#*::}"
      # One "::" only, and no stray single colon at either end of a half.
      [[ "$right" != *::* && "$left" != :* && "$left" != *: && "$right" != :* && "$right" != *: ]] \
        || { _cidr_bad "bad address"; return; }
      l=() r=()
      [[ -z "$left" ]] || IFS=: read -ra l <<<"$left"
      [[ -z "$right" ]] || IFS=: read -ra r <<<"$right"
      (( ${#l[@]} + ${#r[@]} <= 7 )) || { _cidr_bad "bad address"; return; }
      g=("${l[@]}")
      for (( i = ${#l[@]} + ${#r[@]}; i < 8; i++ )); do g+=(0); done
      g+=("${r[@]}")
    else
      [[ "$addr" != :* && "$addr" != *: ]] || { _cidr_bad "bad address"; return; }
      IFS=: read -ra g <<<"$addr"
      (( ${#g[@]} == 8 )) || { _cidr_bad "bad address"; return; }
    fi
    for i in "${g[@]}"; do
      _cidr_hex "$i" || { _cidr_bad "bad address"; return; }
    done
    if (( 16#${g[0]} == 0 && 16#${g[1]} == 0 && 16#${g[2]} == 0 && 16#${g[3]} == 0 \
      && 16#${g[4]} == 0 && 16#${g[5]} == 0xffff )); then
      _cidr_bad "IPv4-mapped address"; return
    fi
    # Host bits: every bit from position BITS on must be zero.
    for i in 0 1 2 3 4 5 6 7; do
      v=$(( 10#$bits - i * 16 ))
      (( v >= 16 )) && continue
      (( v < 0 )) && v=0
      (( (16#${g[$i]} & ((1 << (16 - v)) - 1)) == 0 )) || { _cidr_bad "host bits set"; return; }
    done
  fi
  _cidr_out="$s"
}

cidr_valid() {
  local LC_ALL=C
  _cidr_check "$1" "$2" || { echo "cidr: ${_cidr_err}" >&2; return 1; }
  printf '%s\n' "${_cidr_out}"
}

cidr_filter() {
  local LC_ALL=C fam="$1" line t n=0 _cidr_list=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    t="${line#"${line%%[!"${_cidr_ws}"]*}"}"
    t="${t%"${t##*[!"${_cidr_ws}"]}"}"
    [[ -z "$t" || "$t" == \#* ]] && continue
    _cidr_check "$fam" "$t" || { echo "cidr: line $n: ${_cidr_err}" >&2; return 1; }
    _cidr_list+=("${_cidr_out}")
  done
  (( ${#_cidr_list[@]} > 0 )) || { echo "cidr: no ${fam/v/IPv} prefixes" >&2; return 1; }
  printf '%s\n' "${_cidr_list[@]}"
}
