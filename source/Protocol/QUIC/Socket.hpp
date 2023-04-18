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
		
		struct Address {
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
			
			std::string to_string() const;
		};
		
		struct LocalAddress : public Address {
			std::uint32_t interface_index = 0;
			
			std::string to_string() const;
		};
		
		std::optional<LocalAddress> local_address(msghdr *msg, int family);
		
		enum class ECN : std::uint8_t {
			// The not-ECT codepoint '00' indicates a packet that is not using ECN.
			UNSPECIFIED = 0x00,
			
			// The ECN-Capable Transport (ECT) codepoints `10` and `01` are set by the data sender to indicate that the end-points of the transport protocol are ECN-capable; we call them ECT(0) and ECT(1) respectively. The phrase "the ECT codepoint" in this documents refers to either of the two ECT codepoints.  Routers treat the ECT(0) and ECT(1) codepoints as equivalent.  Senders are free to use either the ECT(0) or the ECT(1) codepoint to indicate ECT, on a packet-by-packet basis.
			CAPABLE_ECT_1 = 0x01,
			CAPABLE_ECT_0 = 0x02,
			
			// The CE codepoint '11' is set by a router to indicate congestion to the end nodes.  Routers that have a packet arriving at a full queue drop the packet, just as they do in the absence of ECN.
			CONGESTION_EXPERIENCED = 0x03,
		};
		
		// msghdr_get_ecn gets ECN bits from |msg|.  |family| is the address
		// family from which packet is received.
		ECN msghdr_get_ecn(msghdr *msg, int family);

		// fd_set_ecn sets ECN bits |ecn| to |fd|.  |family| is the address
		// family of |fd|.
		void set_ecn(int fd, int family, unsigned int ecn);

		// fd_set_rec v_ecn sets socket option to |fd| so that it can receive
		// ECN bits.
		void set_recv_ecn(int fd, int family);

		// fd_set_ip_mtu_discover sets IP(V6)_MTU_DISCOVER socket option to fd.
		void set_ip_mtu_discover(int fd, int family);

		// fd_set_ip_dontfrag sets IP(V6)_DONTFRAG socket option to fd.
		void set_ip_dontfrag(int fd, int family);
		
		class Socket
		{
		public:
			Socket(int descriptor, const Address & address);
			Socket(int descriptor, const addrinfo * address);
			~Socket();
			
			int descriptor() const {return _descriptor;}
			const Address & address() const {return _address;}
			
			static Socket connect(const char * host, const char * service);
			
			size_t send_packet(const void * data, std::size_t size, const Destination & destination, ECN ecn = ECN::UNSPECIFIED);
			size_t receive_packet(void * data, std::size_t size, Address & address, ECN & ecn);
			
		private:
			int _descriptor = 0;
			Address _address;
		};
	}
}
