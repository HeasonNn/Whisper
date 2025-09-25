#include "analyzerWorker.hpp"

#include <boost/functional/hash.hpp>

using namespace Whisper;

using flow_hash_4_t = tuple5_conn4;
using flow_H_table_entry_4_t = shared_ptr<tuple5_flow4>;
using flow_H_table_4_t = unordered_map<flow_hash_4_t, flow_H_table_entry_4_t, boost::hash<flow_hash_4_t>> ;

using flow_hash_6_t = tuple5_conn6;
using flow_H_table_entry_6_t = shared_ptr<tuple5_flow6>;
using flow_H_table_6_t = unordered_map<flow_hash_6_t, flow_H_table_entry_6_t, boost::hash<flow_hash_6_t>>;

#define EPS 1e-9
#define HUG 1e10


static inline auto __get_double_ts() -> double_t {
    struct timeval ts;
    gettimeofday(&ts, nullptr);
    return ts.tv_sec + ts.tv_usec*(1e-6);
}


bool AnalyzerWorkerThread::run(){
    const size_t NUM_TRAIN_DATA = p_learner->p_learner_config->num_train_data;

    flow4_records = make_shared<std::vector<std::shared_ptr<flow_record_t>>>();
    centers = torch::zeros({(long) p_learner->get_K(), (long) (p_analyzer_config->n_fft / 2) + 1});

    auto& raw_data = *pkt_meta_ptr;
    size_t split_pos = std::max(
        NUM_TRAIN_DATA, 
        static_cast<size_t>(raw_data.size() * p_analyzer_config->train_ratio)
    );

    m_is_train = true;
    LOGF("AnalyzerWorkerThread: Start training phase...");

    vector<size_t> local_cache;
    for (size_t idx = 0; idx < raw_data.size(); ++idx) {
        local_cache.emplace_back(idx);

        if (m_is_train && idx >= split_pos) {
            if (!local_cache.empty()) {
                wave_analyze(local_cache);
                local_cache.clear();
            }
            m_is_train = false;
            LOGF("AnalyzerWorkerThread: Start testing phase...");
        }

        if ((idx + 1) % NUM_TRAIN_DATA == 0) {
            wave_analyze(local_cache);
            local_cache.clear();
        }
    }

    if (!local_cache.empty()) {
        wave_analyze(local_cache);
        local_cache.clear();
    }

    if (p_analyzer_config->save_to_file) {
        save_res_json();
    }

    return true;
}


void AnalyzerWorkerThread::wave_analyze(vector<size_t> data){   
    vector<shared_ptr<basic_packet>> raw_data;
    raw_data.reserve(data.size());
    for(auto idx : data){
        raw_data.emplace_back(pkt_meta_ptr->at(idx));
    }

    const auto cur_len = raw_data.size();
    static const double_t min_interval_time = 1e-5;

    unordered_map<uint32_t, vector<size_t> > mp;
    for (size_t i = 0; i < cur_len; i++) {
        auto pkt = raw_data[i];
        if (typeid(*pkt) != typeid(basic_packet4)) continue;
        const auto _p_rep = dynamic_pointer_cast<basic_packet4>(pkt);
        uint32_t addr = (ntohl(tuple_get_src_addr(_p_rep->flow_id)));
        analysis_pkt_len += _p_rep->len;
        if(mp.find(addr) == mp.end()){
            mp.insert(pair<uint32_t, vector<size_t> >(addr, vector<size_t>()));
        }
        mp[addr].push_back(i);
    }

    decltype(mp)::const_iterator iter_mp;
    for (iter_mp = mp.cbegin(); iter_mp != mp.cend(); iter_mp++) {
        const auto & _ve = iter_mp->second;
        if(_ve.size() < 2 * p_analyzer_config->n_fft) continue;

        for (size_t i = _ve.size() - 1; i > 0; i --) {
            raw_data[_ve[i]]->ts -= raw_data[_ve[i - 1]]->ts;
            if (raw_data[_ve[i]]->ts <= 0) {
                raw_data[_ve[i]]->ts = min_interval_time;
            }
        }
        raw_data[_ve[0]]->ts = min_interval_time;

        torch::Tensor ten = torch::zeros(_ve.size());
        for (int i = 0; i < _ve.size(); i++) {
            ten[i] = weight_transform(raw_data[_ve[i]]);
        }

        torch::Tensor window = torch::hann_window(p_analyzer_config->n_fft);
        torch::Tensor ten_fft = torch::stft(
            ten,
            p_analyzer_config->n_fft,
            c10::nullopt,      // hop_length
            c10::nullopt,      // win_length
            window,            // window
            true,              // center
            "reflect",         // pad_mode
            false,             // normalized
            true,              // onesided
            true               // return_complex
        );        

        torch::Tensor ten_power = ten_fft.abs().pow(2);
        ten_power = ten_power.squeeze();

        torch::Tensor ten_res = ((ten_power + 1).log2()).permute({1, 0});
        ten_res = torch::where(torch::isnan(ten_res), torch::full_like(ten_res, 0), ten_res);
        ten_res = torch::where(torch::isinf(ten_res), torch::full_like(ten_res, 0), ten_res);

        if (m_is_train) {
            torch::Tensor ten_temp;
            if (ten_res.size(0) > p_analyzer_config->mean_win_train + 1 && !p_learner->reach_learn()) {
                vector<vector<double_t> > data_to_add;
                for (size_t i = 0; i < p_analyzer_config->num_train_sample; i ++) {
                    size_t start_index = rand() % (ten_res.size(0) - 1 - p_analyzer_config->mean_win_train);
                    ten_temp = ten_res.slice(0, start_index, start_index + p_analyzer_config->mean_win_train).mean(0);
                    vector<double_t> _dt;
                    for(size_t j = 0; j < ten_temp.size(0); j ++) {
                        _dt.push_back((double_t) ten_temp[j].item<double_t>());
                    }
                    data_to_add.push_back(_dt);
                }
                p_learner->add_train_data(data_to_add);
            } else {
                ten_temp =  ten_res.mean(0);
                vector<double_t> data_to_add;
                for(size_t j = 0; j < ten_temp.size(0); j ++) {
                    data_to_add.push_back((double_t) ten_temp[j].item<double_t>());
                }
                p_learner->add_train_data(data_to_add);
            }

            if (p_learner->reach_learn() && !p_learner->start_learn) {
                if (p_analyzer_config->mode_verbose) LOGF("Analyer: trigger the training of learner.");
                p_learner->start_train();
            }

            if (p_learner->finish_learn) {
                analysis_start_time = __get_double_ts();

                analysis_pkt_len = 0;
                analysis_pkt_num = 0;

                const auto & train_res = p_learner->train_result;
                for (size_t i = 0; i < train_res.size(); i ++) {
                    for (size_t j = 0; j < train_res[0].size(); j ++) {
                        centers[i][j] = train_res[i][j];
                    }
                }

                if(p_analyzer_config->mode_verbose) LOGF("Analyer: enter execution mode.");
                m_is_train = false;
            }
        }

        // test
        else {
            double min_dist = max_cluster_dist;
            int assigned_cluster = -1;
            if (ten_res.size(0) > p_analyzer_config->mean_win_test) {
                double_t _max_dist = 0;
                int _assigned_cluster = -1;
                for (size_t i = 0; i + p_analyzer_config->mean_win_test < ten_res.size(0); i += p_analyzer_config->mean_win_test) {
                    torch::Tensor tt = ten_res.slice(0, i, i + p_analyzer_config->mean_win_test).mean(0);
            
                    double_t _min_dist = max_cluster_dist;
                    int _local_cluster = -1;
                    for (size_t j = 0; j < centers.size(0); j++) {
                        double d = torch::norm(tt - centers[j]).item<double_t>();
                        if (d < _min_dist) {
                            _min_dist = d;
                            _local_cluster = j;
                        }
                    }
            
                    if (_min_dist > _max_dist) {
                        _max_dist = _min_dist;
                        _assigned_cluster = _local_cluster;
                    }
                }
                min_dist = _max_dist;
                assigned_cluster = _assigned_cluster;
            } else {
                torch::Tensor tt = ten_res.mean(0);
                double_t _min_dist = max_cluster_dist;
                int _local_cluster = -1;
                for (size_t j = 0; j < centers.size(0); j++) {
                    double d = torch::norm(tt - centers[j]).item<double_t>();
                    if (d < _min_dist) {
                        _min_dist = d;
                        _local_cluster = j;
                    }
                }
                min_dist = _min_dist;
                assigned_cluster = _local_cluster;
            }
    
            if (p_analyzer_config->save_to_file) {
                vector<size_t> rid_vec;
                rid_vec.reserve(_ve.size());
                for(auto id : _ve) rid_vec.emplace_back(data[id]);

                bool is_malicious = std::any_of(rid_vec.begin(), rid_vec.end(),
                    [&](size_t idx) {return pkt_label_ptr->at(idx) == 1;}
                );
                
                auto buf_loc = flow_record_t {
                    .addr = iter_mp->first,
                    .distence = min_dist, 
                    .assigned_cluster = assigned_cluster, 
                    .is_malicious = is_malicious
                };

                auto buf_loc_ptr = make_shared<flow_record_t>(buf_loc);
                flow4_records->push_back(buf_loc_ptr);
            }
        }
    }
}


// 2020.12.8
auto inline AnalyzerWorkerThread::weight_transform(const shared_ptr<Whisper::basic_packet> info) -> double_t 
{
    uint16_t tp_value = 10;
    switch (info->tp)
    {
    case 5:
        tp_value = 10;      // TYPE_ICMP 		= 10,
        break;
    case 17: 
        tp_value = 1;       // TYPE_TCP_SYN 	= 1
        break;
    case 33:
        tp_value = 1000;    // TYPE_TCP_ACK 	= 1000
        break;
    case 49:
        tp_value = 1001;    // TYPE_TCP_ACK + TYPE_TCP_SYN 	= 1001
        break;
    case 97:
        tp_value = 40;      // TYPE_TCP_FIN 	= 40
        break;
    case 129:
        tp_value = 1;       // TYPE_TCP_RST 	= 1
        break;
    case 161:
        tp_value = 1;       // TYPE_TCP_RST + TYPE_TCP_ACK 	= 2
        break;
    case 257:
        tp_value = 3;       // TYPE_UDP 		= 3
        break;
    default:
        break;
    }
    return info->len * 10.0 + tp_value / 10.0 + -log2(info->ts) * 15.68;
}


auto AnalyzerWorkerThread::get_overall_performance() const -> pair<double_t, double_t> 
{
	return {
        (((double_t) sum_analysis_pkt_num) /  (analysis_end_time - analysis_start_time)) / 1e6, 
        ((((double_t) sum_analysis_pkt_len) * 8.0) /  (analysis_end_time - analysis_start_time)) / 1e9
    };
}


auto AnalyzerWorkerThread::save_res_json() const -> bool 
{
	if (access(p_analyzer_config->save_dir.c_str(), 0) == -1) {
        system(("mkdir " + p_analyzer_config->save_dir).c_str());
    }

    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm * ptm = std::localtime(&now_time);

    char time_buf[32];
    std::strftime(time_buf, sizeof(time_buf), "_%Y%m%d_%H%M", ptm);

    ostringstream oss;
    oss << p_analyzer_config->save_dir 
        << p_analyzer_config->save_file_prefix 
        << time_buf
        << ".json";
    string file_name = oss.str();

    json j_array;
    
    for(size_t i = 0; i < flow4_records->size(); i ++) {
        json _j;
        const auto& cur_flow_record = flow4_records->at(i);
        _j.push_back(cur_flow_record->addr);
        _j.push_back(cur_flow_record->distence);
        _j.push_back(cur_flow_record->assigned_cluster);
        _j.push_back(cur_flow_record->is_malicious);
        j_array.push_back(_j);
    }

    json j_res;
    j_res["Results"] = j_array;
    ofstream of(file_name);
    if (of) {
        of << j_res;
        of.close();
        printf("Analyzer: save result to %s \n", file_name.c_str());
        return true;
    } else {
        return false;
    }
}


// Config form json file
auto AnalyzerWorkerThread::configure_via_json(const json & jin) -> bool 
{
    if (p_analyzer_config != nullptr) {
        WARN("Analyzer configuration overlap.");
        return false;
    }

    p_analyzer_config = make_shared<AnalyzerConfigParam>();
    if (p_analyzer_config == nullptr) {
        WARNF("Analyzer configuration paramerter bad allocation.");
        return false;
    }
    
    LOGF("AnalyzerWorkerThread: start configuring analyzer parameters via JSON.");

    try {

        // parameters for frequency domain representations
        if (jin.count("n_fft")) {
            p_analyzer_config->n_fft = 
                static_cast<decltype(p_analyzer_config->n_fft)>(jin["n_fft"]);
        }

        // machine learning
        if (jin.count("mean_win_train")) {
            p_analyzer_config->mean_win_train = 
                static_cast<decltype(p_analyzer_config->mean_win_train)>(jin["mean_win_train"]);
        }
        if (jin.count("mean_win_test")) {
            p_analyzer_config->mean_win_test = 
                static_cast<decltype(p_analyzer_config->mean_win_test)>(jin["mean_win_test"]);
        }
        if (jin.count("num_train_sample")) {
            p_analyzer_config->num_train_sample = 
                static_cast<decltype(p_analyzer_config->num_train_sample)>(jin["num_train_sample"]);
        }
        if (jin.count("num_train_sample")) {
            p_analyzer_config->num_train_sample = 
                static_cast<decltype(p_analyzer_config->num_train_sample)>(jin["num_train_sample"]);
        }
        if (jin.count("train_ratio")) {
            p_analyzer_config->train_ratio = 
                static_cast<decltype(p_analyzer_config->train_ratio)>(jin["train_ratio"]);
        }

        // verbose parameters
        if (jin.count("mode_verbose")) {
            p_analyzer_config->mode_verbose = 
                static_cast<decltype(p_analyzer_config->mode_verbose)>(jin["mode_verbose"]);
        }
        if (jin.count("init_verbose")) {
            p_analyzer_config->init_verbose = 
                static_cast<decltype(p_analyzer_config->init_verbose)>(jin["init_verbose"]);
        }
        if (jin.count("center_verbose")) {
            p_analyzer_config->center_verbose = 
                static_cast<decltype(p_analyzer_config->center_verbose)>(jin["center_verbose"]);
        }
        if (jin.count("ip_verbose")) {
            p_analyzer_config->ip_verbose = 
                static_cast<decltype(p_analyzer_config->ip_verbose)>(jin["ip_verbose"]);
        }
        if (jin.count("speed_verbose")) {
            p_analyzer_config->speed_verbose = 
                static_cast<decltype(p_analyzer_config->speed_verbose)>(jin["speed_verbose"]);
        }
        if (jin.count("speed_verbose")) {
            p_analyzer_config->speed_verbose = 
                static_cast<decltype(p_analyzer_config->speed_verbose)>(jin["speed_verbose"]);
        }
        if (jin.count("verbose_interval")) {
            p_analyzer_config->verbose_interval = 
                static_cast<decltype(p_analyzer_config->verbose_interval)>(jin["verbose_interval"]);
            if (p_analyzer_config->verbose_interval < 0) {
                WARNF("Invalid verbose time interval.");
                throw logic_error("Parse error Json tag: verbose_interval\n");
            }
        }
        if (jin.count("verbose_ip_target")) {
            p_analyzer_config->verbose_ip_target = 
                static_cast<decltype(p_analyzer_config->verbose_ip_target)>(jin["verbose_ip_target"]);
            if (!IPv4Address(p_analyzer_config->verbose_ip_target).isValid()) {
                p_analyzer_config->ip_verbose = false;
                WARNF("Invalid target verbose IP address.");
                throw logic_error("Parse error Json tag: verbose_ip_target\n");
            }
        } else {
            p_analyzer_config->ip_verbose = false;
        }

        // save to file
        if (jin.count("save_to_file")) {
            p_analyzer_config->save_to_file = 
                static_cast<decltype(p_analyzer_config->save_to_file)>(jin["save_to_file"]);
        }
        if (jin.count("save_dir")) {
            p_analyzer_config->save_dir = 
                static_cast<decltype(p_analyzer_config->save_dir)>(jin["save_dir"]);
        }
        if (jin.count("save_file_prefix")) {
            p_analyzer_config->save_file_prefix = 
                static_cast<decltype(p_analyzer_config->save_file_prefix)>(jin["save_file_prefix"]);
        }

        /////////////////////////////////////////// Critical Paramerters

    } catch (exception & e) {
        WARN(e.what());
        return false;
    }

    return true;
}
