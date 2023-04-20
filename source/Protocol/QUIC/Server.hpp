//
//  Server.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include <memory>

#include "Connection.hpp"
#include "TLS/ServerSession.hpp"
#include "ngtcp2/ngtcp2.h"

namespace Protocol
{
	namespace QUIC
	{
		class Binding;
		
		class Server : public Connection
		{
			void setup(TLS::ServerContext & tls_context, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_path *path, uint32_t client_chosen_version, ngtcp2_settings *settings, ngtcp2_transport_params *params, const ngtcp2_mem *mem = nullptr);
		public:
			Server(Binding * binding, Configuration & configuration, TLS::ServerContext & tls_context, Socket & socket, const Address & remote_address, const ngtcp2_pkt_hd & packet_header);
			virtual ~Server();
			
			void process_packet(Socket & socket, const Address & remote_address, const Byte *data, std::size_t length, ECN ecn);
			
		protected:
			void drain();
			void close();
			
			Binding * _binding;
			std::unique_ptr<TLS::ServerSession> _tls_session;
			
			ngtcp2_cid _scid;
		};
	}
}
