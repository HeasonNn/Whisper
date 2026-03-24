#!/usr/bin/env python3
"""Generate Whisper config files for all datasets."""
import json
import os
from pathlib import Path

# Base directories - container paths
DATA_DIR = "/home/hs/data"  # data is mounted as-is
OUTPUT_DIR = "/workspace/Whisper/config"  # config dir in container
RESULT_DIR = "/workspace/Whisper/results"  # results dir in container

# Dataset configurations
DATASETS = {
    "hypervision": {
        "path": f"{DATA_DIR}/hypervision",
        "files": []
    },
    "ids2017": {
        "path": f"{DATA_DIR}/CICIDS2017",
        "files": []
    },
    "unsw": {
        "path": f"{DATA_DIR}/UNSW_NB15",
        "files": []
    },
    "cic_apt_iot": {
        "path": f"{DATA_DIR}/CIC_APT_IIoT2024",
        "files": []
    },
    "ciciot2025": {
        "path": f"{DATA_DIR}/CICIIOT2025",
        "files": []
    },
    "dohbrw": {
        "path": f"{DATA_DIR}/DoHBrw",
        "files": []
    }
}

def get_base_config(dataset_name, file_prefix):
    """Generate base config for a dataset file."""
    return {
        "Parser": {
            "dataset_dir": f"{DATASETS[dataset_name]['path']}/{file_prefix}.data",
            "label_dir": f"{DATASETS[dataset_name]['path']}/{file_prefix}.label"
        },
        "Learner": {
            "val_K": 10,
            "num_train_data": 2000,
            "save_result": False,
            "save_result_file": "",
            "load_result": False,
            "load_result_file": "",
            "verbose": True
        },
        "Analyzer": {
            "n_fft": 32,
            "mean_win_train": 100,
            "mean_win_test": 100,
            "num_train_sample": 100,
            "train_ratio": 0.5,
            "mode_verbose": True,
            "init_verbose": True,
            "center_verbose": True,
            "ip_verbose": False,
            "speed_verbose": True,
            "verbose_interval": 100000,
            "save_to_file": True,
            "save_dir": f"{RESULT_DIR}/{dataset_name}/",
            "save_file_prefix": file_prefix
        }
    }

def discover_dataset_files(dataset_name):
    """Find all .data files in a dataset directory."""
    dataset_path = Path(DATASETS[dataset_name]['path'])
    if not dataset_path.exists():
        print(f"Warning: Dataset path not found: {dataset_path}")
        return []
    
    data_files = sorted(dataset_path.glob("*.data"))
    return [f.stem for f in data_files]

def main():
    # Create output directories
    os.makedirs(RESULT_DIR, exist_ok=True)
    
    for dataset_name in DATASETS:
        print(f"\nProcessing dataset: {dataset_name}")
        
        # Discover files
        file_prefixes = discover_dataset_files(dataset_name)
        if not file_prefixes:
            print(f"  No .data files found in {DATASETS[dataset_name]['path']}")
            continue
        
        print(f"  Found {len(file_prefixes)} files")
        
        # Create output directory
        config_dir = Path(OUTPUT_DIR) / dataset_name
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Create result directory
        result_dir = Path(RESULT_DIR) / dataset_name
        result_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate config for each file
        for prefix in file_prefixes:
            config = get_base_config(dataset_name, prefix)
            config_path = config_dir / f"{prefix}.json"
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
        
        print(f"  Generated {len(file_prefixes)} config files")

if __name__ == "__main__":
    main()
