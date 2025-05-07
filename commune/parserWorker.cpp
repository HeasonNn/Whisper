#include "parserWorker.hpp"


using namespace Whisper;

// bool ParserWorkerThread::parser_from_pcap() 
// {
// 	parser_start_time = get_time_spec();

// 	pcpp::PcapFileReaderDevice *reader = new pcpp::PcapFileReaderDevice(parser_config_ptr->pcap_dir);
//     if (!reader->open())
//     {
//         cout << "Error opening pcap file!" << endl;
//         return false;
//     }
	
// 	LOGF("ParserWorkerThread: Start parsing packets...");

//     pcpp::RawPacket packet;
// 	const auto _f_get_meta_pkt_info = [&packet, this]() -> shared_ptr<basic_packet> {
// 		pcpp::Packet parsedPacket(&packet, false, pcpp::IP, pcpp::OsiModelNetworkLayer);

// 		// ignore the packets out of the scope of TCP/IPv4 protocol stack
// 		if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
// 			pcpp::IPv4Layer * IPlay = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

// 			uint32_t addr = IPlay->getSrcIPv4Address().toInt();
// 			uint16_t length = ntohs(IPlay->getIPv4Header()->totalLength);
// 			double_t ts = GET_DOUBLE_TS(packet.getPacketTimeStamp());

// 			uint16_t type_code = type_identify_mp::TYPE_UNKNOWN;
// 			IPlay->parseNextLayer();
// 			pcpp::ProtocolType type_next = IPlay->getNextLayer()->getProtocol();
// 			if (type_next == pcpp::TCP) {
// 				pcpp::TcpLayer* tcp_layer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
// 				if (tcp_layer->getTcpHeader()->synFlag) {
// 					type_code = type_identify_mp::TYPE_TCP_SYN;
// 				} else if (tcp_layer->getTcpHeader()->finFlag) {
// 					type_code = type_identify_mp::TYPE_TCP_FIN;
// 				} else if (tcp_layer->getTcpHeader()->rstFlag) {
// 					type_code = type_identify_mp::TYPE_TCP_RST;
// 				} else {
// 					type_code = type_identify_mp::TYPE_TCP;
// 				}
// 			} else if (type_next == pcpp::UDP) {
// 				type_code = type_identify_mp::TYPE_UDP;
// 			} else {
// 				type_code = type_identify_mp::TYPE_UNKNOWN;
// 			}
			
// 			return make_shared<basic_packet>(addr, type_code, length, ts);
			
// 		} else {
// 			return nullptr;
// 		}
// 	};

// 	while (reader->getNextPacket(packet)) {

// 		const auto p_meta = _f_get_meta_pkt_info();
// 		if (p_meta == nullptr) {
// 			continue;
// 		}

// 		pkt_meta_ptr->push_back(p_meta);
// 		++packet_count;
// 	}

// 	return true;

// }

bool ParserWorkerThread::parser_from_data() 
{
	__START_FTIMMER__

	ifstream _ifd(parser_config_ptr->dataset_dir);
	vector<string> string_temp;
	string _line;
	int line_cnt = 0;
	while (getline(_ifd, _line)) {
		string_temp.push_back(_line);
		line_cnt++;
	}

	_ifd.close();

	size_t num_pkt = string_temp.size();
	LOGF("[Debug] num_pkt: %ld, line_cnt: %d", num_pkt, line_cnt);

	pkt_meta_ptr = make_shared<decltype(pkt_meta_ptr)::element_type>(num_pkt);

	const size_t multiplex_num = 64;
	const u_int32_t part_size = ceil(((double) num_pkt) / ((double) multiplex_num));
	vector<pair<size_t, size_t> > _assign;
	for (size_t core = 0, idx = 0; core < multiplex_num; ++ core, idx = min(idx + part_size, num_pkt)) {
		_assign.push_back({idx, min(idx + part_size, num_pkt)});
	}
	auto __f = [&] (size_t _from, size_t _to) -> void {
		for (size_t i = _from; i < _to; ++ i) {
			const string & str = string_temp[i];
			if (str[0] == '4') {
				const auto make_pkt = make_shared<basic_packet4>(str);
				pkt_meta_ptr->at(i) = make_pkt;
			} else if (str[0] == '6') {
				const auto make_pkt = make_shared<basic_packet6>(str);
				pkt_meta_ptr->at(i) = make_pkt;
			} else {
				const auto make_pkt = make_shared<basic_packet_bad>();
				pkt_meta_ptr->at(i) = make_pkt;
			}
		}
	};

	vector<thread> vt;
	for (size_t core = 0; core < multiplex_num; ++core) {
		vt.emplace_back(__f, _assign[core].first, _assign[core].second);
	}

	for (auto & t : vt)
		t.join();


	ifstream _ifl(parser_config_ptr->label_dir);
	pkt_label_ptr = make_shared<decltype(pkt_label_ptr)::element_type>();
	string ll;
	_ifl >> ll;
	for (const char a: ll) {
		pkt_label_ptr->push_back(a == '1');
	}
	_ifl.close();

	LOGF("[Debug] pkt_label_ptr->size(): %ld, pkt_meta_ptr->size(): %ld.", 
		pkt_label_ptr->size(), 
		pkt_meta_ptr->size()
	);

	assert(pkt_label_ptr->size() == pkt_meta_ptr->size());

	__STOP_FTIMER__
	__PRINTF_EXE_TIME__
	return true;
}

bool ParserWorkerThread::run() 
{
	if (parser_config_ptr == nullptr) {
		FATAL_ERROR("NULL parser configuration parameters.");
	}

	pkt_meta_ptr = make_shared<vector<shared_ptr<basic_packet>>>();
	if (pkt_meta_ptr == nullptr) {
		FATAL_ERROR("Meta data array: bad allocation.");
	}

	pkt_label_ptr = std::make_shared<std::vector<uint8_t>>();
	if (pkt_label_ptr == nullptr) {
		FATAL_ERROR("Packet label array: bad allocation.");
	}

	// parser_from_pcap();
	parser_from_data();
	return true;
}


auto ParserWorkerThread::configure_via_json(const json & jin) -> bool  
{
	if (parser_config_ptr != nullptr) {
		WARN("Analyzer configuration overlap.");
		return false;
	}

	parser_config_ptr = make_shared<ParserConfigParam>();
	if (parser_config_ptr == nullptr) {
		WARNF("Parser configuration paramerter bad allocation.");
		return false;
	}

	try {
		if (jin.count("pcap_dir")) {
			parser_config_ptr->pcap_dir = 
				static_cast<decltype(parser_config_ptr->pcap_dir)>(jin["pcap_dir"]);
		}
		if (jin.count("dataset_dir")) {
			parser_config_ptr->dataset_dir = 
				static_cast<decltype(parser_config_ptr->dataset_dir)>(jin["dataset_dir"]);
		}
		if (jin.count("label_dir")) {
			parser_config_ptr->label_dir = 
				static_cast<decltype(parser_config_ptr->label_dir)>(jin["label_dir"]);
		}
	} catch (exception & e) {
		WARN(e.what());
		return false;
	}
	return true;
}