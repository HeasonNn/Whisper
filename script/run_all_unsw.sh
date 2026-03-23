#!/usr/bin/env bash

set -eux

CONFIG_DIR="../config/unsw"

shopt -s nullglob
for cfg in "${CONFIG_DIR}"/*.json; do
  item="$(basename "${cfg}" .json)"
  echo "[RUN] ${item}"
  ./Whisper -config "${cfg}" # &
done
