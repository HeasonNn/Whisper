#pragma once

#include "whisper_common.hpp"
#include "parserWorker.hpp"
#include "kMeansLearner.hpp"
#include "analyzerWorker.hpp"


#define DISP_PARAM


namespace Whisper
{


class ParserWorkerThread;
class AnalyzerWorkerThread;
class KMeansLearner;


struct DeviceConfigParam final {

    DeviceConfigParam() {}
    virtual ~DeviceConfigParam() {}
    DeviceConfigParam & operator=(const DeviceConfigParam &) = delete;
    DeviceConfigParam(const DeviceConfigParam &) = delete;
};


struct ThreadStateManagement final {

	bool stop = true;

	vector<shared_ptr<ParserWorkerThread> > parser_worker_thread_vec;
    vector<shared_ptr<AnalyzerWorkerThread> > analyzer_worker_thread_vec;

	ThreadStateManagement() = default;
    virtual ~ThreadStateManagement() {}
    ThreadStateManagement & operator=(const ThreadStateManagement &) = default;
    ThreadStateManagement(const ThreadStateManagement &) = default;

    ThreadStateManagement(const decltype(parser_worker_thread_vec) & _p_vec,
                          const decltype(analyzer_worker_thread_vec) & _a_vec): 
                          parser_worker_thread_vec(_p_vec), analyzer_worker_thread_vec(_a_vec), stop(false) {}

};


class whisper_detector final {
    
private:

    bool verbose = true;

    shared_ptr<const DeviceConfigParam> p_configure_param;

    json j_cfg_analyzer;
    json j_cfg_kmeans;
    json j_cfg_parser;

public:
    
    // Default constructor
    explicit whisper_detector() {
        LOGF("Device configure uses default parameters");
    }

    explicit whisper_detector(const decltype(p_configure_param) _p): p_configure_param(_p) {
        LOGF("Device configure uses specific parameters");
    }

    explicit whisper_detector(const json & jin) {
        if (configure_via_json(jin)) {
            LOGF("Device configure uses json");
        } else {
            LOGF("Json object invalid");
        }
    }

    virtual ~whisper_detector() {};
    whisper_detector & operator=(const whisper_detector &) = delete;
    whisper_detector(const whisper_detector &) = delete;

    // Do init after all configures are done
    void run();

    // Config form json file
    auto configure_via_json(const json & jin) -> bool;
};

}