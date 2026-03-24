# Whisper

![Licence](https://img.shields.io/github/license/fuchuanpu/Whisper)
![Last](https://img.shields.io/github/last-commit/fuchuanpu/Whisper)
![Language](https://img.shields.io/github/languages/count/fuchuanpu/Whisper)
![Language](https://img.shields.io/github/languages/code-size/fuchuanpu/Whisper)

The prototype source code of the paper:  
___Realtime Robust Malicious Traffic Detection via Frequency Domain Analysis___  
[Chuanpu Fu](https://www.fuchuanpu.cn/), [Qi Li](https://sites.google.com/site/qili2012), [Meng Shen](https://cs.bit.edu.cn/szdw/jsml/js/shenmeng/index.htm), [Ke Xu](http://www.thucsnet.org/xuke.html).  
ACM Conference on Computer and Communications Security ([CCS 2021](https://dl.acm.org/doi/10.1145/3460120.3484585))

```bibtex
@inproceedings{CCS21-Whisper,
  author       = {Chuanpu Fu and
                  Qi Li and
                  Meng Shen and
                  Ke Xu},
  title        = {Realtime Robust Malicious Traffic Detection via Frequency Domain Analysis},
  booktitle    = {{CCS} '21: 2021 {ACM} {SIGSAC} Conference on Computer and Communications
                  Security, Virtual Event, Republic of Korea, November 15 - 19, 2021},
  pages        = {3431--3446},
  publisher    = {{ACM}},
  year         = {2021},
}
```

---

## Background
Malicious traffic detection systems are designed to identify malicious traffic on the forwarding path. As a promising security paradigm, machine learning (ML) was leveraged for the _zero-day attack issue_. Due to the improper trade-off between feature _scale_ and _efficiency_, the existing can not realize _robust_ and _realtime_ detection. We present the frequency domain features, which reduce the scale of traditional per-packet features, avoid information loss in the flow-level features. Finally, in this repo. Finally, we present the Whisper prototype, an end-to-end detector in a 10 Gb scale network in this repo.

> For more details, plsease refer to our paper in ACM CCS 2021.

---

## Install

> Feel free to contact me, when something went wrong. 

### Hardware preparation  

Before software installation please check your hardware platform according to the testbed setup in the paper. Here I list some recommendations:  
- Ensure all your NICs and CPUs supports Intel DPDK, find the versions using `lspci` and `proc/cpuinfo` and check the lists in [DPDK Support](http://core.dpdk.org/supported/)
- Check the connectivity of fiber and laser modules using ICMP echo and static routing. Note that, direct connections are preferred to prevent errors.
- To adapt the packet rate of MAWI datasets, ensure the NICs support at least 10 Gbps throughput. Measuring the throughput using `iperf3` is recommended.
- At least 10 GB of memory is needed, for the DPDK huge pages. And the server for Whisper main modules needs at least 17 cores.

### Software preparation

0. __Install compile toolchain.__   
The prototype was tested in Ubuntu 18.04 and 20.04. It is compiled by `cmake` + `ninja` + `gcc`, please find the correct versions and install the tool chain using `apt-get`. 

1. __Install DPDK.__  
Whisper used DPDK for highspeed packet parsering. Therefore, please refer to the [__DPDK Offical Guide__](http://doc.dpdk.org/guides/linux_gsg/) and install the libraries. It is worth noting that, the compatibility of DPDK 21 is unknown and the version listed in the paper is preferred.

2. __Install LibPcap++.__  
Whisper used LibPcap++ encapsulated DPDK to reduce the size of the source code. Make sure the libpcap++ version is compatible with the DPDK version. Note that, the Libpcap++ with DPDK support can only be obtained via source code compiling. Here is the official the guide for [Libpcap++ Installation](https://pcapplusplus.github.io/docs/install/build-source/linux).

3. __Install PyTorch C++__  
Whisper used Pytorch C++ to implement matrix and sequence transformations. Download the Offical released form [Pytorch Release](https://pytorch.org/get-started/locally/). The ABI for CPU only is enough and make sure you selected cxx11 supported version.

4. __Install mlpcak__
Whisper used mlpack for unsupervised learning. Please used the correct commands for C++ stable version in [mlpack Installation](https://www.mlpack.org/getstarted.html).

---

## Usage

### Build

Firstly, check the path of downloaded PyTorch C++ is configured in CMakeLists.txt correctly. Then compile the prototype source code.
```shell
mkdir build && cd $_
cmake -G Ninja ..
ninja
```

### Run on Datasets

We provide scripts for running Whisper on multiple network intrusion detection datasets.

#### 1. Generate Config Files

```bash
python3 scripts/generate_configs.py
```

This script:
- Discovers all `.data` files in dataset directories
- Generates corresponding config JSON files in `config/<dataset>/`
- Creates result directories in `results/<dataset>/`

Supported datasets:
- `hypervision` - Hypervision dataset
- `ids2017` - CICIDS2017
- `unsw` - UNSW_NB15
- `cic_apt_iot` - CIC_APT_IIoT2024
- `ciciot2025` - CICIIOT2025
- `dohbrw` - DoHBrw

#### 2. Run Whisper

Run all datasets:
```bash
./scripts/run_all.sh
```

Run a specific dataset:
```bash
./scripts/run_all.sh ids2017
```

Each config file has a 5-minute timeout. Logs are saved to `logs/` directory.

#### 3. Extract Results

After running Whisper, extract packet-level evaluation metrics:
```bash
python3 scripts/extract_results.py
```

Options:
```bash
python3 scripts/extract_results.py --help
usage: extract_results.py [-h] [--results_dir RESULTS_DIR] [--output_dir OUTPUT_DIR]

Extract Whisper results and compute packet-level AUC/F1 metrics.

optional arguments:
  -h, --help            show this help message and exit
  --results_dir RESULTS_DIR
                        Directory containing Whisper results (default: results)
  --output_dir OUTPUT_DIR
                        Directory for output CSV files (default: results/_summary)
```

#### 4. Output Format

The extraction script generates CSV files in `results/_summary/`:

| File | Description |
|------|-------------|
| `results_raw.csv` | Raw results for each file (algorithm, dataset, file, attack_category, auc, f1, precision, recall, ...) |
| `results_by_dataset.csv` | Aggregated metrics per dataset |
| `results_by_attack_category.csv` | Aggregated metrics per attack category |
| `results_by_algorithm.csv` | Aggregated metrics per algorithm |
| `results_by_file.csv` | Aggregated metrics per file |
| `results_grouped.csv` | Results grouped by dataset and attack category |

**Key metrics:**
- `auc` - Area Under ROC Curve (packet-level, with sampling for large datasets)
- `f1` - F1 Score (best threshold found)
- `precision` - Precision at best threshold
- `recall` - Recall at best threshold

### Attack Category Grouping

Attack categories are grouped following the eTRACE methodology. See `scripts/attack_groups.py` for group definitions:

| Dataset | Attack Categories |
|---------|-------------------|
| CICIDS2017 | DoS_DDoS, BruteForce, Web_Scan, Bot |
| CICIIOT2025 | BruteForce, DoS_DDoS, Malware, MITM, Recon_Scan, Web_Attack |
| UNSW_NB15 | DoS_DDoS, Recon_Scan, Exploit_Malware, Generic |
| Hypervision | BruteForce, DoS_DDoS, Malware, Recon_Scan, Web_Attack |
| CIC_APT_IIoT2024 | APT |
| DoHBrw | Tunneling |

---

## Project Structure

```
Whisper/
├── build/                   # Compiled binary
├── commune/                 # C++ source files
├── config/                  # Generated config files
│   ├── hypervision/
│   ├── ids2017/
│   ├── unsw/
│   ├── cic_apt_iot/
│   ├── ciciot2025/
│   └── dohbrw/
├── results/                 # Whisper output results
│   ├── _summary/           # CSV evaluation summaries
│   └── <dataset>/          # Per-dataset JSON results
├── scripts/                 # Analysis scripts
│   ├── attack_groups.py    # Attack category grouping
│   ├── extract_results.py  # Packet-level AUC/F1 evaluation
│   ├── generate_configs.py # Config file generator
│   └── run_all.sh          # Batch runner
├── script/                  # Original project scripts
├── CMakeLists.txt
├── main.cpp
└── README.md
```

---

## FAQ
0. __Strange link stage warnings.__ After the compiling, we got the warnings from `ld` below, but `ninja` generated binary successfully. What is the impact of the abnormity? 
```
/usr/bin/ld: /home/libtorch/lib/libtorch_cpu.so: .dynsym local symbol at index 149 (>= sh_info of 2)
```
__Answer:__ The link stage warning is generated because of the mismatch of the compiler version for PyTorch and Whisper. You can find a closer version, but it has no side-effect from my experience.

1. __On the feasibility of deploying Whisper in cloud.__

__Answer:__ I have tried to deploy it on AWS EC2 and other commercial clouds. Finally, I succeeded with huge efforts but still cannot realize the throughput measured on the physical testbed due to the performance limitations of virtual network interfaces. Therefore, I do not recommend the deployment in a multi-tenant network because the . _If you have some advice, please contact us._

---

## Contact Me
[Chuanpu Fu](fuchuanpu20@mails.tsinghua.edu.cn)
