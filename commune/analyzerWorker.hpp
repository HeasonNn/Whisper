#pragma once

#include "../common.hpp"
#include "whisper_common.hpp"
#include "packet_basic.hpp"
#include "parserWorker.hpp"
#include "kMeansLearner.hpp"
#include "flow_define.hpp"

#include <torch/torch.h>


namespace Whisper
{

struct basic_packet;
class ParserWorkerThread;
class KMeansLearner;
class DeviceConfig;


struct AnalyzerConfigParam final {

    // Number of fft
    size_t n_fft = 50;

    // Mean Window Train
    size_t mean_win_train = 50;
    // Mean Window Test
    size_t mean_win_test = 100;
    // Number of train sampling
    size_t num_train_sample = 50;

    double_t train_ratio = 0.75;

    // Save results to file
    bool save_to_file = false;
    // File path
    string save_dir = "";
    // File tag
    string save_file_prefix = "";

    // Verbose configure
    double_t verbose_interval = 5.0;
    bool init_verbose = false;
    bool mode_verbose = false;
    bool center_verbose = false;
    bool speed_verbose = false;
    bool ip_verbose = false;
    string verbose_ip_target = "";

    auto inline display_params() const -> void {
        printf("[Whisper Analyzer Configuration]\n");

        printf("ML realated param:\n");
        printf("Traing window size: %ld, Testing window size: %ld, Num. Training sample: %ld\n",
        mean_win_train, mean_win_test, num_train_sample);

        printf("Frequency domain analysis realated param:\n");
        printf("FFT component size: %ld\n", n_fft);

        if (save_to_file) {
            printf("Saving related param:\n");
            printf("Saving DIR: %s, Saving prefix: %s\n", 
            save_dir.c_str(), save_file_prefix.c_str());
        }

        stringstream ss;
        ss << "Verbose mode: {";
        if (init_verbose) ss << "Init,";
        if (mode_verbose) ss << "Mode,";
        if (center_verbose) ss << "Center,";
        if (speed_verbose) ss << "Speed,";
        if (ip_verbose) ss << "IP: " << verbose_ip_target;
        ss << "}";
        printf("%s (Interval %4.2lfs)\n\n", ss.str().c_str(), verbose_interval);

    }

    AnalyzerConfigParam() = default;
    virtual ~AnalyzerConfigParam() {}
    AnalyzerConfigParam & operator=(const AnalyzerConfigParam &) = delete;
    AnalyzerConfigParam(const AnalyzerConfigParam &) = delete;

};



class AnalyzerWorkerThread final {

	friend class whisper_detector;

private:
    bool m_is_train = true;

	shared_ptr<vector<shared_ptr<basic_packet>>> pkt_meta_ptr;
    shared_ptr<vector<uint8_t>> pkt_label_ptr;

	uint64_t analysis_pkt_len = 0;
	uint64_t analysis_pkt_num = 0;
	uint64_t sum_analysis_pkt_num = 0;
	uint64_t sum_analysis_pkt_len = 0;
	double_t analysis_start_time, analysis_end_time;

    // The result of train, i.e. the clustring centers
    torch::Tensor centers;

    shared_ptr<KMeansLearner> p_learner;
    shared_ptr<AnalyzerConfigParam> p_analyzer_config;

    typedef struct {
        uint32_t addr;
        double_t distence;
        int assigned_cluster;
        bool is_malicious;
    }  flow_record_t;

    shared_ptr<vector<shared_ptr<flow_record_t>>> flow4_records;
    // shared_ptr<vector<shared_ptr<tuple5_flow6>>> flow6_records;

    const double_t max_cluster_dist = 1e12;

    void wave_analyze(vector<size_t> data);
    auto static inline weight_transform(const shared_ptr<Whisper::basic_packet> info) -> double_t;

public:

    AnalyzerWorkerThread(
        const shared_ptr<vector<shared_ptr<basic_packet>>> _pkt_meta_ptr, 
        const shared_ptr<vector<uint8_t>> _pkt_label_ptr,
        const shared_ptr<KMeansLearner> _pl
    ): pkt_meta_ptr(_pkt_meta_ptr), p_learner(_pl), pkt_label_ptr(_pkt_label_ptr) {}

    virtual ~AnalyzerWorkerThread() {}
    AnalyzerWorkerThread & operator=(const AnalyzerWorkerThread &) = delete;
    AnalyzerWorkerThread(const AnalyzerWorkerThread &) = delete;

    bool run();

    auto configure_via_json(const json & jin) -> bool;

    auto save_res_json() const -> bool;

    auto get_overall_performance() const -> pair<double_t, double_t>;

};


}

