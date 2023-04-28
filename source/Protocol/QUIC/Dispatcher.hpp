//
//  Dispatcher.hpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 20/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "TLS/ServerContext.hpp"
#include "Server.hpp"
#include "Socket.hpp"
#include "ngtcp2/ngtcp2.h"

#include <unordered_map>
#include <memory>

namespace Protocol
{
	namespace QUIC
	{
		class Configuration;
		
		// The Dispatcher class is responsible for receiving and routing incoming QUIC packets to their appropriate destination. This class is used by the QUIC implementation to listen for incoming packets on a UDP socket and route those packets to the appropriate connection based on the connection ID. If a packet is received for a connection that does not exist, the Dispatcher will create a new server instance to handle the connection.
		class Dispatcher
		{
		public:
			Dispatcher(Configuration & configuration, TLS::ServerContext & tls_context);
			virtual ~Dispatcher();
			
			const Configuration & configuration() const noexcept {return _configuration;}
			const TLS::ServerContext & tls_context() const noexcept {return _tls_context;}
			
			void associate(const ngtcp2_cid *cid, Server * server);
			void disassociate(const ngtcp2_cid *cid);
			
			void remove(Server * server);
			
			// Create a server instance to handle a new connection.
			virtual Server * create_server(Socket &socket, const Address &address, const ngtcp2_pkt_hd &packet_header) = 0;
			
			// Wait for incoming connections and create servers to handle them.
			void listen(Socket & socket);
			
			// Process a single incoming packet from a given remote address.
			void process_packet(Socket & socket, const Address &remote_address, const Byte * data, std::size_t length, ECN ecn, ngtcp2_version_cid &version_cid);
			
			void send_packets();
			
		protected:
			Configuration & _configuration;
			TLS::ServerContext & _tls_context;
			
			void send_version_negotiation(Socket & socket, ngtcp2_version_cid &version_cid, const Address &remote_address);
			
		private:
			// Associates a connection ID with a server instance:
			std::unordered_map<std::string, Server *> _servers;
		};
	}
}
