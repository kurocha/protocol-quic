//
//  Socket.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 8/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <optional>
#include <vector>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <ngtcp2/ngtcp2.h>

namespace Protocol
{
	namespace QUIC
	{
		using Byte = std::uint8_t;
		using Destination = ngtcp2_addr;
		
		// A value based wrapper around ngtcp2_sockaddr_union.
		struct Address {
			static std::optional<Address> extract(msghdr *message, int family);
			static std::vector<Address> resolve(const char * host, const char * service, int family = AF_UNSPEC, int socktype = SOCK_DGRAM, int flags = AI_PASSIVE|AI_ADDRCONFIG);
			
			ngtcp2_sockaddr_union data;
			ngtcp2_socklen length = 0;
			
			Address() = default;
			
			Address(ngtcp2_sockaddr * sockaddr, ngtcp2_socklen length)
			{
				std::copy_n(reinterpret_cast<const std::uint8_t *>(sockaddr), length, reinterpret_cast<std::uint8_t *>(&data));
				this->length = length;
			}
			
			Address(const Destination & destination) : Address(destination.addr, destination.addrlen) {}
			Address(const addrinfo * addr) : Address(addr->ai_addr, addr->ai_addrlen) {}
			
			operator Destination() {return {&data.sa, length};}
			operator const Destination() const {return {const_cast<ngtcp2_sockaddr*>(&data.sa), length};}
			
			bool operator==(const Address & other) const {
				return length == other.length && std::memcmp(&data, &other.data, length) == 0;
			}
			
			int family() const {return data.sa.sa_family;}
			
			std::string to_string() const;
		};
		
		enum class ECN : std::uint8_t {
			// The not-ECT codepoint '00' indicates a packet that is not using ECN.
			UNSPECIFIED = 0x00,
			
			// The ECN-Capable Transport (ECT) codepoints `10` and `01` are set by the data sender to indicate that the end-points of the transport protocol are ECN-capable; we call them ECT(0) and ECT(1) respectively. The phrase "the ECT codepoint" in this documents refers to either of the two ECT codepoints.  Routers treat the ECT(0) and ECT(1) codepoints as equivalent.  Senders are free to use either the ECT(0) or the ECT(1) codepoint to indicate ECT, on a packet-by-packet basis.
			CAPABLE_ECT_1 = 0x01,
			CAPABLE_ECT_0 = 0x02,
			
			// The CE codepoint '11' is set by a router to indicate congestion to the end nodes.  Routers that have a packet arriving at a full queue drop the packet, just as they do in the absence of ECN.
			CONGESTION_EXPERIENCED = 0x03,
		};
		
		class Socket
		{
		public:
			// The address provided here is
			Socket(int descriptor, const Address & address);
			Socket(int descriptor, const addrinfo * address);
			~Socket();
			
			int descriptor() const {return _descriptor;}
			const Address & address() const {return _address;}
			
			// Connect to the remote host and service/port.
			static Socket connect(const char * host, const char * service);
			
			size_t send_packet(const void * data, std::size_t size, const Destination & destination, ECN ecn = ECN::UNSPECIFIED);
			size_t receive_packet(void * data, std::size_t size, Address & address, ECN & ecn);
			
		private:
			int _descriptor = 0;
			ECN _ecn = ECN::UNSPECIFIED;
			
			Address _address;
		};
	}
}
