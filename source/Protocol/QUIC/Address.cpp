//
//  Address.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 23/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Address.hpp"
#include "Defer.hpp"

#include <cassert>
#include <iostream>
#include <algorithm>

namespace Protocol
{
	namespace QUIC
	{
		std::string Address::to_string() const
		{
			if (length == 0) return "<unknown>";
			
			char name[NI_MAXHOST];
			char service[NI_MAXSERV];
			
			if (getnameinfo(&data.sa, length, name, sizeof(name), service, sizeof(service), NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				throw std::runtime_error("getnameinfo");
			}
			
			return std::string(name) + ":" + service;
		}
		
		std::optional<Address> Address::extract(msghdr *message, int family)
		{
			if (family == AF_INET) {
				for (auto cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
						auto pktinfo = reinterpret_cast<in_pktinfo *>(CMSG_DATA(cmsg));
						Address address;
						address.length = sizeof(address.data.in);
						address.data.in.sin_family = AF_INET;
						address.data.in.sin_addr = pktinfo->ipi_addr;
						return address;
					}
				}
			}
			else if (family == AF_INET6) {
				for (auto cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
						auto pktinfo = reinterpret_cast<in6_pktinfo *>(CMSG_DATA(cmsg));
						Address address;
						address.length = sizeof(address.data.in6);
						address.data.in6.sin6_family = AF_INET6;
						address.data.in6.sin6_addr = pktinfo->ipi6_addr;
						return address;
					}
				}
			}
			
			return {};
		}
		
		std::vector<Address> Address::resolve(const char * host, const char * service, int family, int type, int flags)
		{
			std::vector<Address> addresses;
			
			addrinfo hints;
			std::memset(&hints, 0, sizeof(hints));
			
			hints.ai_family = family;
			hints.ai_socktype = type;
			hints.ai_flags = flags;
			
			addrinfo * result = nullptr;
			
			if (getaddrinfo(host, service, &hints, &result) != 0) {
				throw std::runtime_error("getaddrinfo");
			}
			
			Defer free_result([&]{
				freeaddrinfo(result);
			});
			
			for (auto iterator = result; iterator; iterator = iterator->ai_next) {
				addresses.emplace_back(iterator->ai_addr, iterator->ai_addrlen);
			}
			
			return addresses;
		}
		
		Address::Address()
		{
			length = 0;
			std::memset(&data, 0xFA, sizeof(data));
		}
		
		Address::~Address()
		{
			length = 0;
			std::memset(&data, 0xFE, sizeof(data));
		}
		
		void Address::set(const ngtcp2_sockaddr * sockaddr, ngtcp2_socklen length)
		{
			assert(length <= sizeof(data));
			std::copy_n(reinterpret_cast<const std::uint8_t *>(sockaddr), length, reinterpret_cast<std::uint8_t *>(&data));
			this->length = length;
		}
		
		std::ostream & operator<<(std::ostream & output, const Address & address)
		{
			output << "<Address family=" << address.data.sa.sa_family << " address=" << address.to_string() << ">";
			
			return output;
		}
		
		std::ostream & operator<<(std::ostream & output, const Destination & destination)
		{
			output << "<Destination address=" << Address(destination) << ">";
			
			return output;
		}
	}
}
