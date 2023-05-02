//
//  Server.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include <Scheduler/Semaphore.hpp>

#include <memory>
#include <iosfwd>

#include "Connection.hpp"
#include "TLS/ServerSession.hpp"
#include "ngtcp2/ngtcp2.h"

namespace Protocol
{
	namespace QUIC
	{
		class Dispatcher;
		
		// The Server class is a sub-class of Connection that represents a QUIC server connection. This class is used by the QUIC implementation to manage the state of a QUIC server connection.
		// Each Server instance is associated with a single QUIC connection and a remote Client instance.
		class Server : public Connection
		{
			void setup(TLS::ServerContext & tls_context, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_path *path, uint32_t client_chosen_version, ngtcp2_settings *settings, ngtcp2_transport_params *params, const ngtcp2_mem *mem = nullptr);
		public:
			Server(Dispatcher & binding, Configuration & configuration, TLS::ServerContext & tls_context, Socket & socket, const Address & remote_address, const ngtcp2_pkt_hd & packet_header, ngtcp2_cid *ocid = nullptr);
			virtual ~Server();
			
			void process_packet(Socket & socket, const Address & remote_address, const Byte *data, std::size_t length, ECN ecn);
			
			void accept();
			
		protected:
			void drain();
			
			Dispatcher & _binding;
			std::unique_ptr<TLS::ServerSession> _tls_session;
			
			Scheduler::Semaphore _received_packets = 0;
			
			ngtcp2_cid _scid;
			
			void print(std::ostream & output) const override;
		};
	}
}
