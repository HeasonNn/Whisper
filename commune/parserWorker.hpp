#pragma once

#include "whisper_common.hpp"
#include "analyzerWorker.hpp"


using namespace std;
using namespace pcpp;

namespace Whisper
{


class AnalyzerWorkerThread;
class DeviceConfig;


struct ParserConfigParam final {

	string pcap_dir;
	string dataset_dir;
	string label_dir;

	ParserConfigParam() = default;
    virtual ~ParserConfigParam() {}
    ParserConfigParam & operator=(const ParserConfigParam &) = delete;
    ParserConfigParam(const ParserConfigParam &) = delete;
};

class ParserWorkerThread {

	friend class AnalyzerWorkerThread;
	friend class DeviceConfig;

private:

	shared_ptr<ParserConfigParam> parser_config_ptr;

	size_t packet_count;

	// statistical variables
	mutable vector<uint64_t> parsed_pkt_len;
	mutable vector<uint64_t> parsed_pkt_num;
	mutable vector<uint64_t> sum_parsed_pkt_num;
	mutable vector<uint64_t> sum_parsed_pkt_len;
	mutable double_t parser_start_time, parser_end_time;

	// Read-Write exclution for per-packet Metadata
	mutable sem_t semaphore;
	void inline acquire_semaphore() const {
		sem_wait(&semaphore);
	}
	void inline release_semaphore() const {
		sem_post(&semaphore);
	}

	enum type_identify_mp : uint16_t {
		TYPE_TCP_SYN 	= 1,
		TYPE_TCP_FIN 	= 40,
		TYPE_TCP_RST 	= 1,
		TYPE_TCP_ACK 	= 1000,
		TYPE_TCP 		= 1000,
		TYPE_UDP 		= 3,
		TYPE_ICMP 		= 10,
		TYPE_IGMP 		= 9,
		TYPE_UNKNOWN 	= 10,
	};

public:

	// Collect the per-packets metadata
	shared_ptr<vector<shared_ptr<basic_packet>>> pkt_meta_ptr;
	shared_ptr<vector<uint8_t>> pkt_label_ptr;
	
	ParserWorkerThread() = default;
	virtual ~ParserWorkerThread() {}
	ParserWorkerThread & operator=(const ParserWorkerThread&) = delete;
	ParserWorkerThread(const ParserWorkerThread&) = delete;

	// bool parser_from_pcap();

    bool parser_from_data();
	
	bool run();

	auto configure_via_json(const json & jin) -> bool;

};

}
