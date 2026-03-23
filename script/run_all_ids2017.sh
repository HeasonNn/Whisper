#!/usr/bin/env bash

set -eux

ARR=(
  "Bot"
  "Brute_Force"
  "DDoS_LOIT"
  "DoS_GoldenEye"
  "DoS_Slowhttptest"
  "DoS_slowloris"
  "FTP_Patator"
  "Infiltration"
  "PortScan"
  "SSH_Patator"
  "XSS"
)

for item in ${ARR[@]}; do
    ./Whisper -config ../config/ids2017/${item}.json  # &
done
