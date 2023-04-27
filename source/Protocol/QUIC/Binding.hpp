//
//  Binding.hpp
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
		
		class Binding
		{
		public:
			Binding(Configuration & configuration, TLS::ServerContext & tls_context);
			virtual ~Binding();
			
			void associate(const ngtcp2_cid *cid, Server * server);
			void disassociate(const ngtcp2_cid *cid);
			
			void remove(Server * server);
			
			// Create a server instance to handle a new connection.
			virtual Server * create_server(Socket &socket, const Address &address, const ngtcp2_pkt_hd &packet_header) = 0;
			
			// Wait for incoming connections and create servers to handle them.
			void listen(const Address &address);
			
			// Process a single incoming packet from a given remote address.
			void process_packet(Socket & socket, const Address &remote_address, const Byte * data, std::size_t length, ECN ecn, ngtcp2_version_cid &version_cid);
			
			void send_packets();
			
		protected:
			Configuration & _configuration;
			TLS::ServerContext & _tls_context;
			
			void send_version_negotiation(Socket & socket, ngtcp2_version_cid &version_cid, const Address &remote_address);
			
		private:
			std::vector<std::unique_ptr<Socket>> _sockets;
			
			// Associates a connection ID with a server instance:
			std::unordered_map<std::string, Server *> _servers;
		};
	}
}
