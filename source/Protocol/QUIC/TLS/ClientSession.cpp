//
//  ClientSession.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 7/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "ClientSession.hpp"

#include <array>
#include <stdexcept>

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			ClientSession::ClientSession(ClientContext &client_context, ngtcp2_conn *connection) : Session(client_context, connection), _negotiated_protocols(client_context.protocols())
			{
				_context.ptls = ptls_client_new(client_context.native_handle());
				
				if (_context.ptls == nullptr) {
					throw std::runtime_error("Could not create client session!");
				}
				
				set_connection_reference();
				
				auto &handshake_properties = _context.handshake_properties;
				handshake_properties.client.negotiated_protocols.list = _negotiated_protocols.names.data();
				handshake_properties.client.negotiated_protocols.count = _negotiated_protocols.names.size();
				
				setup_extensions();
				
				if (ngtcp2_crypto_picotls_configure_client_session(&_context, connection)) {
					throw std::runtime_error("Could not configure client session!");
				}
			}
			
			ClientSession::~ClientSession()
			{
				
			}
			
			bool ClientSession::early_data_accepted() const {
				return _context.handshake_properties.client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED;
			}
		}
	}
}
