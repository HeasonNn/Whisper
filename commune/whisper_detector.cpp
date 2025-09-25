#include "whisper_detector.hpp"
#include "parserWorker.hpp"

using namespace Whisper;
using namespace pcpp;


void whisper_detector::run() {

	LOGF("Configure Whisper runtime environment.");

	const auto parser_ptr = make_shared<ParserWorkerThread>();
	parser_ptr->configure_via_json(j_cfg_parser);
	parser_ptr->run();

	const auto& k_learner_ptr = make_shared<KMeansLearner>();
	k_learner_ptr->configure_via_json(j_cfg_kmeans);
	
	const auto analyzer_ptr = make_shared<AnalyzerWorkerThread>(parser_ptr->pkt_meta_ptr, parser_ptr->pkt_label_ptr, k_learner_ptr);
	analyzer_ptr->configure_via_json(j_cfg_analyzer);
	analyzer_ptr->run();
}


auto whisper_detector::configure_via_json(const json & jin) -> bool {
	
	if (p_configure_param) {
		LOGF("Device init param modification.");
		p_configure_param = NULL;
	}

	try {
		const auto _device_param = make_shared<DeviceConfigParam>();
		if (_device_param == nullptr) {
			WARN("device paramerter bad allocation");
			throw bad_alloc();
		}

		if (jin.find("Analyzer") != jin.end()) {
			j_cfg_analyzer = jin["Analyzer"];
		} else {
			WARN("Analyzer configuration not found, use default.");
		}
		if (jin.find("Learner") != jin.end()) {
			j_cfg_kmeans = jin["Learner"];
		} else {
			WARN("Learner configuration not found, use default.");
		}
		if (jin.find("Parser") != jin.end()) {
			j_cfg_parser = jin["Parser"];
		} else {
			WARN("Parser configuration not found, use default.");
		}

	} catch(exception & e) {
		FATAL_ERROR(e.what());
	}

	return true;
}
