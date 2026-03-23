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
	
	const auto analyzer_ptr = make_shared<AnalyzerWorkerThread>(
		parser_ptr->pkt_meta_ptr, parser_ptr->pkt_label_ptr, k_learner_ptr
	);
	analyzer_ptr->configure_via_json(j_cfg_analyzer);

	size_t sample_size = parser_ptr->pkt_meta_ptr->size();
	size_t train_sample_size = 
		static_cast<size_t>(sample_size * analyzer_ptr->p_analyzer_config->train_ratio);

	k_learner_ptr->p_learner_config->num_train_data = train_sample_size;

	analyzer_ptr->run();
}


auto whisper_detector::configure_via_json(const json & jin) -> bool {
	
	if (p_configure_param) {
		LOGF("Device init param modification.");
		p_configure_param = NULL;
	}

	j_cfg_analyzer = jin["Analyzer"];
	j_cfg_kmeans = jin["Learner"];
	j_cfg_parser = jin["Parser"];

	return true;
}
