#include <gflags/gflags.h>

#include "commune/whisper_detector.hpp"
#include "common.hpp"


using namespace std;


DEFINE_string(config, "../configTemplate.json", "Configure Whisper via JSON file.");


int main(int argc, char** argv) {
    __START_FTIMMER__
    
    // parse command line
    google::ParseCommandLineFlags(&argc, &argv, true);

    // read all from json file
    json config_j;
    try {
        ifstream fin(FLAGS_config, ios::in);
        fin >> config_j;
    } catch (exception & e) {
        FATAL_ERROR(e.what());
    }
    
    const auto config_init_ptr = make_shared<Whisper::whisper_detector>();
    config_init_ptr->configure_via_json(config_j);
    config_init_ptr->run();
    
    __STOP_FTIMER__
    __PRINTF_EXE_TIME__

}

