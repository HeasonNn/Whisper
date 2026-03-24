#!/bin/bash
# Run Whisper on all datasets
# Usage: ./run_all.sh [dataset_name]

set -e

WHISPER_BIN="/workspace/Whisper/build/Whisper"
CONFIG_DIR="/workspace/Whisper/config"
LOG_DIR="/workspace/Whisper/logs"

mkdir -p "$LOG_DIR"

run_dataset() {
    local dataset=$1
    local config_subdir="$CONFIG_DIR/$dataset"
    
    if [ ! -d "$config_subdir" ]; then
        echo "[ERROR] Config directory not found: $config_subdir"
        return 1
    fi
    
    local count=0
    local total=$(ls -1 "$config_subdir"/*.json 2>/dev/null | wc -l)
    
    echo "========================================"
    echo "Dataset: $dataset ($total files)"
    echo "========================================"
    
    for cfg in "$config_subdir"/*.json; do
        [ -f "$cfg" ] || continue
        count=$((count + 1))
        local name=$(basename "$cfg" .json)
        local log_file="$LOG_DIR/${dataset}_${name}.log"
        
        echo "[$count/$total] Running: $name"
        
        if timeout 300 "$WHISPER_BIN" -config "$cfg" > "$log_file" 2>&1; then
            echo "  -> OK"
        else
            echo "  -> FAILED (exit: $?)"
        fi
    done
    
    echo "Completed $count files for $dataset"
}

# Main
if [ -n "$1" ]; then
    run_dataset "$1"
else
    # Run all 6 datasets
    for ds in hypervision ids2017 unsw cic_apt_iot ciciot2025 dohbrw; do
        run_dataset "$ds"
    done
fi

echo "All done!"
