#pragma once

#include "../common.hpp"

using namespace std;
using namespace pcpp;

namespace Whisper {

// ——————————————————————————————————————————————————————
// 地址定义
union __pkt_addr6 {
    __uint128_t num_rep;
    uint8_t byte_rep[16];
};

using pkt_addr4_t = uint32_t;
using pkt_addr6_t = __uint128_t;
using pkt_len_t = uint16_t;
using pkt_port_t = uint16_t;
using pkt_ts_t = timespec;

// ——————————————————————————————————————————————————————
// Packet协议类型定义
using pkt_code_t = uint16_t;

enum class pkt_type_t : uint8_t {
    IPv4,
    IPv6,
    ICMP,
    IGMP,
    TCP_SYN,
    TCP_ACK,
    TCP_FIN,
    TCP_RST,
    UDP,
    UNKNOWN
};

constexpr const char* type2name[] = {
    "IPv4", "IPv6", "ICMP", "IGMP",
    "TCP_SYN", "TCP_ACK", "TCP_FIN", "TCP_RST",
    "UDP", "UNKNOWN"
};

inline void set_pkt_type_code(pkt_code_t& cd, pkt_type_t t) {
    cd |= (1 << static_cast<uint8_t>(t));
}
inline constexpr auto get_pkt_type_code(pkt_type_t t) -> pkt_code_t {
    return (1 << static_cast<uint8_t>(t));
}
inline constexpr auto test_pkt_type_code(pkt_code_t cd, pkt_type_t t) -> bool {
    return cd & (1 << static_cast<uint8_t>(t));
}

// ——————————————————————————————————————————————————————
// 协议栈类型定义
using stack_code_t = uint16_t;

enum class stack_type_t : uint8_t {
    F_ICMP,
    F_IGMP,
    F_TCP,
    F_UDP,
    F_UNKNOWN,
};

constexpr const char* stack2name[] = {
    "ICMP", "IGMP", "TCP", "UDP", "UNKNOWN"
};

inline constexpr auto get_pkt_stack_code(stack_type_t st) -> stack_code_t {
    return (1 << static_cast<uint8_t>(st));
}

inline auto convert_packet2stack_code(pkt_code_t pc) -> stack_code_t {
    if (test_pkt_type_code(pc, pkt_type_t::ICMP)) {
        return get_pkt_stack_code(stack_type_t::F_ICMP);
    }
    if (test_pkt_type_code(pc, pkt_type_t::IGMP)) {
        return get_pkt_stack_code(stack_type_t::F_IGMP);
    }
    if (test_pkt_type_code(pc, pkt_type_t::UDP)) {
        return get_pkt_stack_code(stack_type_t::F_UDP);
    }
    if (test_pkt_type_code(pc, pkt_type_t::UNKNOWN)) {
        return get_pkt_stack_code(stack_type_t::F_UNKNOWN);
    }
    return get_pkt_stack_code(stack_type_t::F_TCP); // 默认认为是TCP类
}

// ——————————————————————————————————————————————————————
// Tuple类型定义
using tuple2_conn4 = tuple<pkt_addr4_t, pkt_addr4_t>;
using tuple2_conn6 = tuple<pkt_addr6_t, pkt_addr6_t>;
using tuple4_conn4 = tuple<pkt_addr4_t, pkt_addr4_t, pkt_port_t, pkt_port_t>;
using tuple4_conn6 = tuple<pkt_addr6_t, pkt_addr6_t, pkt_port_t, pkt_port_t>;
using tuple5_conn4 = tuple<pkt_addr4_t, pkt_addr4_t, pkt_port_t, pkt_port_t, stack_code_t>;
using tuple5_conn6 = tuple<pkt_addr6_t, pkt_addr6_t, pkt_port_t, pkt_port_t, stack_code_t>;

// ——————————————————————————————————————————————————————
// Tuple操作模板
template<typename Tuple>
inline auto tuple_get_src_addr(const Tuple& cn) -> decltype(get<0>(cn)) {
    return get<0>(cn);
}

template<typename Tuple>
inline auto tuple_get_dst_addr(const Tuple& cn) -> decltype(get<1>(cn)) {
    return get<1>(cn);
}

template<typename Tuple>
inline auto tuple_get_src_port(const Tuple& cn) -> decltype(get<2>(cn)) {
    return get<2>(cn);
}

template<typename Tuple>
inline auto tuple_get_dst_port(const Tuple& cn) -> decltype(get<3>(cn)) {
    return get<3>(cn);
}

template<typename Tuple>
inline auto tuple_get_stack(const Tuple& cn) -> decltype(get<4>(cn)) {
    return get<4>(cn);
}

template<typename Tuple>
inline auto tuple_is_stack(const Tuple& cn, stack_type_t tp) -> bool {
    return get<4>(cn) & (1 << static_cast<uint8_t>(tp));
}

// 反转5元组（带Stack）
template<typename Tuple>
inline auto tuple_conn_reverse(const Tuple& cn) -> Tuple {
    return Tuple{get<1>(cn), get<0>(cn), get<3>(cn), get<2>(cn), get<4>(cn)};
}

// 反转4元组（无Stack）
template<typename Tuple>
inline auto tuple_conn_reverse4(const Tuple& cn) -> Tuple {
    return Tuple{get<1>(cn), get<0>(cn), get<3>(cn), get<2>(cn)};
}

// 将4元组扩展为5元组
template<typename Tuple>
inline auto tuple4_extend(const Tuple& cn, const stack_code_t sc) 
    -> tuple<decltype(get<0>(cn)), decltype(get<1>(cn)), decltype(get<2>(cn)), decltype(get<3>(cn)), stack_code_t> 
{
    return {get<0>(cn), get<1>(cn), get<2>(cn), get<3>(cn), sc};
}

// ——————————————————————————————————————————————————————
// 地址字符串转换模块（模板特化版）
template<typename AddrType>
inline auto get_str_addr(const AddrType& ad) -> string;

template<>
inline auto get_str_addr(const pkt_addr4_t& ad) -> string {
    return pcpp::IPv4Address(ad).toString();
}

template<>
inline auto get_str_addr(const pkt_addr6_t& ad) -> string {
    __pkt_addr6 __t;
    __t.num_rep = ad;
    return pcpp::IPv6Address(__t.byte_rep).toString();
}

template<typename AddrType>
inline auto convert_str_addr(const string& str) -> AddrType;

template<>
inline auto convert_str_addr<pkt_addr4_t>(const string& str) -> pkt_addr4_t {
    pcpp::IPv4Address pcpp_ip(str);
    if (str == "0.0.0.0") {
        return 0;
    }
    if (!pcpp_ip.isValid()) {
        throw std::runtime_error("Invalid IPv4 address: " + str);
    }
    return pcpp_ip.toInt();
}

template<>
inline auto convert_str_addr<pkt_addr6_t>(const string& str) -> pkt_addr6_t {
    pcpp::IPv6Address pcpp_ip(str);
    if (!pcpp_ip.isValid()) {
        throw std::runtime_error("Invalid IPv6 address: " + str);
    }
    __pkt_addr6 __t;
    memcpy(__t.byte_rep, pcpp_ip.toBytes(), sizeof(__t));
 
    return __t.num_rep;
};

static auto string_2_uint128(const std::string input) -> __uint128_t {
    const char * str = input.c_str();
    __uint128_t res = 0;
    for (; *str; res = res * 10 + *str++ - '0');
    return res;
}

static auto uint128_2_string(const __uint128_t num) -> std::string {
    __uint128_t mask = -1;
    size_t a, b, c = 1, d;
    char *s = (char *) malloc(2);
    strcpy(s, "0");
    for (mask -= mask / 2; mask; mask >>= 1) {
        for (a = (num & mask) != 0, b = c; b;) {
            d = ((s[--b] - '0') << 1) + a;
            s[b] = "0123456789"[d % 10];
            a = d / 10;
        }
        for (; a; s = (char *) realloc(s, ++c + 1), memmove(s + 1, s, c), *s = "0123456789"[a % 10], a /= 10);
    }
    std::stringstream ss;
    ss << s;
    free(s);
    std::string ret = ss.str();
    return ret;
}

}