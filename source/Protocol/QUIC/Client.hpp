//
//  Client.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 5/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "Connection.hpp"
#include "Configuration.hpp"

#include <cstdint>
#include <memory>
#include <string_view>

#include "TLS/ClientSession.hpp"

namespace Protocol
{
	namespace QUIC
	{
		class Client : public Connection
		{
			void setup(TLS::ClientContext & tls_context, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_path *path, std::uint32_t chosen_version, ngtcp2_settings *settings, ngtcp2_transport_params *params);
			
		public:
			Client(Configuration & configuration, TLS::ClientContext & tls_context, Socket &socket, const Address &remote_address, std::uint32_t chosen_version = NGTCP2_PROTO_VER_V1);
			virtual ~Client();
			
			void connect();
			
			std::uint64_t maximum_local_unidirectional_streams() const {
				return ngtcp2_conn_get_max_local_streams_uni(_connection);
			}
			
		protected:
			std::unique_ptr<TLS::ClientSession> _tls_session;
			
			std::uint32_t _chosen_version;
		};
	}
}
