//
//  Socket.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 8/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "Address.hpp"

#include <Time/Interval.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <optional>
#include <vector>
#include <cstring>
#include <iosfwd>
#include <cassert>

namespace Protocol
{
	namespace QUIC
	{
		using Byte = std::uint8_t;
		using Timestamp = Time::Timestamp;
		
		enum class ECN : std::uint8_t {
			// The not-ECT codepoint '00' indicates a packet that is not using ECN.
			UNSPECIFIED = 0x00,
			
			// The ECN-Capable Transport (ECT) codepoints `10` and `01` are set by the data sender to indicate that the end-points of the transport protocol are ECN-capable; we call them ECT(0) and ECT(1) respectively. The phrase "the ECT codepoint" in this documents refers to either of the two ECT codepoints.  Routers treat the ECT(0) and ECT(1) codepoints as equivalent.  Senders are free to use either the ECT(0) or the ECT(1) codepoint to indicate ECT, on a packet-by-packet basis.
			CAPABLE_ECT_1 = 0x01,
			CAPABLE_ECT_0 = 0x02,
			
			// The CE codepoint '11' is set by a router to indicate congestion to the end nodes.  Routers that have a packet arriving at a full queue drop the packet, just as they do in the absence of ECN.
			CONGESTION_EXPERIENCED = 0x03,
		};
		
		// The Socket class represents a UDP socket, which is used for sending and receiving QUIC packets. This class is used by the QUIC implementation to bind or connect a network socket and send and receive packets over that socket.
		class Socket
		{
			std::string _annotation;
			
		public:
			Socket(int domain, int type = SOCK_DGRAM, int protocol = IPPROTO_UDP);
			~Socket();
			
			const std::string & annotation() const {return _annotation;}
			void annotate(const std::string & annotation) {_annotation = annotation;}
			
			Socket(Socket && other);
			Socket & operator=(Socket && other);
			
			Socket(const Socket &) = delete;
			Socket & operator=(const Socket &) = delete;
			
			int descriptor() const {return _descriptor;}
			
			const Address & local_address() const;
			const Address & remote_address() const;
			
			bool bind(const Address & address);
			bool connect(const Address & address);
			
			void close();
			
			operator bool() const {return _descriptor >= 0;}
			
			// @returns the number of bytes sent, or 0 if a timeout occurred.
			size_t send_packet(const void * data, std::size_t size, const Destination & destination, ECN ecn = ECN::UNSPECIFIED, Timestamp * timeout = nullptr);
			
			// @parameter address is set to the address of the sender (remote peer).
			// @returns the number of bytes received, or 0 if a timeout occurred.
			size_t receive_packet(void * data, std::size_t size, Address & address, ECN & ecn, Timestamp * timeout = nullptr);
			
		private:
			int _descriptor = -1;
			
			// Cached local and remote addresses.
			// May be set by bind/connect.
			mutable Address _local_address, _remote_address;
			
			ECN _ecn = ECN::UNSPECIFIED;
		};
		
		std::ostream & operator<<(std::ostream & output, const Socket & socket);
	}
}
