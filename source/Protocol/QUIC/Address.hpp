//
//  Address.hpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 23/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>
#include <iosfwd>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <ngtcp2/ngtcp2.h>

namespace Protocol
{
	namespace QUIC
	{
		using Destination = ngtcp2_addr;
		
		// A value based wrapper around ngtcp2_sockaddr_union.
		struct Address final {
			static std::optional<Address> extract(msghdr *message, int family);
			static std::vector<Address> resolve(const char * host, const char * service, int family = AF_UNSPEC, int socktype = SOCK_DGRAM, int flags = AI_PASSIVE|AI_ADDRCONFIG);
			
			ngtcp2_sockaddr_union data;
			ngtcp2_socklen length = 0;
			void set(const ngtcp2_sockaddr * sockaddr, ngtcp2_socklen length);
			
			Address();
			~Address();
			
			Address(ngtcp2_sockaddr * sockaddr, ngtcp2_socklen length) {
				set(sockaddr, length);
			}
			
			Address(const Destination & destination) : Address(destination.addr, destination.addrlen) {}
			Address(const addrinfo * addr) : Address(addr->ai_addr, addr->ai_addrlen) {}
			
			Address & operator=(const Address & other) {
				set(&other.data.sa, other.length);
				return *this;
			}
			
			operator bool() const {return length > 0;}
			
			operator Destination() {return {&data.sa, length};}
			operator const Destination() const {return {const_cast<ngtcp2_sockaddr*>(&data.sa), length};}
			
			bool operator==(const Address & other) const {
				return length == other.length && std::memcmp(&data, &other.data, length) == 0;
			}
			
			int family() const {return data.sa.sa_family;}
			
			std::string to_string() const;
		};
		
		std::ostream & operator<<(std::ostream & output, const Address & address);
		std::ostream & operator<<(std::ostream & output, const Destination & destination);
	}
}
