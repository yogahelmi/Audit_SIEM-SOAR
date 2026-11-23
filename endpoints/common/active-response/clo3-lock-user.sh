#!/bin/bash
# CLO3 active response: restrict a user account (PB-04 Privilege escalation).
# Target user = extra_args[0] (sent by Shuffle) or alert.data.srcuser.
# Kebijakan: akun admin yang diizinkan tidak pernah dikunci; akun lain dikunci
# (passwd lock + expire) dan semua prosesnya dihentikan. "delete" = buka kunci.
source /var/ossec/active-response/bin/clo3-lib.sh

USER_NAME=${ARG1:-$(jq -r '.parameters.alert.data.srcuser // empty' <<<"$INPUT_JSON")}
PROTECTED_USERS=" root yoga hafidz ${CLO3_PROTECTED_USERS:-} "

if [ -z "$USER_NAME" ] || ! id "$USER_NAME" >/dev/null 2>&1; then
  report lock-user skipped "${USER_NAME:-none}" "user does not exist"; exit 0
fi
if [[ "$PROTECTED_USERS" == *" $USER_NAME "* ]]; then
  report lock-user skipped "$USER_NAME" "protected admin account (policy)"; exit 0
fi

if [ "$COMMAND" = "delete" ]; then
  usermod -U "$USER_NAME" && chage -E -1 "$USER_NAME"
  if passwd -S "$USER_NAME" | awk '{exit ($2=="L")}'; then
    report unlock-user success "$USER_NAME" "account unlocked"
  else
    report unlock-user failed "$USER_NAME" "account still locked"
  fi
  exit 0
fi

usermod -L "$USER_NAME" && chage -E 0 "$USER_NAME"
pkill -KILL -u "$USER_NAME" 2>/dev/null

# --- Verify ---
if passwd -S "$USER_NAME" | awk '{exit ($2!="L")}'; then
  report lock-user success "$USER_NAME" "account locked, expired, sessions killed"
else
  report lock-user failed "$USER_NAME" "account not locked"
fi
