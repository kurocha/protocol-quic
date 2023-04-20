//
//  Session.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 7/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include "Context.hpp"

#include <string>
#include <optional>

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			class Context;
			
			class Session
			{
			public:
				static Session * get(ptls_t *ptls);
				
				Session(Context &context, ngtcp2_conn *connection);
				virtual ~Session();
				
				ngtcp2_crypto_picotls_ctx *native_handle() {return &_context;}
				
				ngtcp2_conn *connection() {return _connection;}
				
				// Set the name to be validated during the TLS handshake.
				void set_server_name(std::string_view server_name);
				
				// The server name or not set if SNI is not used or failed to negotiate.
				std::optional<std::string> server_name() const;
				
				std::string cipher_name() const;
				std::string selected_protocol() const;
				
			protected:
				ngtcp2_crypto_picotls_ctx _context;
				
				ngtcp2_conn *_connection = nullptr;
				ngtcp2_crypto_conn_ref _crypto_connection_reference;
				
				void set_connection_reference();
				static ngtcp2_crypto_conn_ref * connection_reference(ptls_t *ptls);
				
				std::vector<ptls_raw_extension_t> _extensions;
				void setup_extensions();
			};
		}
	}
}
