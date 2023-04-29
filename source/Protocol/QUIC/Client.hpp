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
#include "TLS/ClientSession.hpp"

#include <cstdint>
#include <memory>
#include <string_view>
#include <iosfwd>

namespace Protocol
{
	namespace QUIC
	{
		// The Client class is a sub-class of Connection that represents a QUIC client connection. This class is used by the QUIC implementation to manage the state of a QUIC client connection.
		// Each Client instance is associated with a single QUIC connection and a remote Server instance.
		class Client : public Connection
		{
			void setup(TLS::ClientContext & tls_context, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_path *path, std::uint32_t chosen_version, ngtcp2_settings *settings, ngtcp2_transport_params *params);
			
		public:
			Client(Configuration & configuration, TLS::ClientContext & tls_context, Socket &socket, const Address &remote_address, std::uint32_t chosen_version = NGTCP2_PROTO_VER_V1);
			virtual ~Client();
			
			void connect();
			
			void extend_maximum_local_bidirectional_streams(std::uint64_t maximum_streams) override;
			
		protected:
			std::unique_ptr<TLS::ClientSession> _tls_session;
			std::uint32_t _chosen_version;
			
			void print(std::ostream & output) const override;
		};
	}
}
