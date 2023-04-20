//
//  Session.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 7/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Session.hpp"
#include "ngtcp2/ngtcp2_crypto.h"
#include "picotls.h"

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			static ngtcp2_conn* get_connection(ngtcp2_crypto_conn_ref *reference) {
				auto session = static_cast<Session *>(reference->user_data);
				
				return session->connection();
			}
			
			Session * Session::get(ptls_t *ptls)
			{
				auto reference = connection_reference(ptls);
				
				if (reference) {
					// This next line of code scares me...
					return static_cast<Session *>(reference->user_data);
				} else {
					return nullptr;
				}
			}
			
			Session::Session(Context &context, ngtcp2_conn *connection) : _connection(connection), _crypto_connection_reference{get_connection, this}
			{
				ngtcp2_crypto_picotls_ctx_init(&_context);
				
				// Binds the current session to the connection:
				ngtcp2_conn_set_tls_native_handle(_connection, &_context);
			}
			
			Session::~Session()
			{
				ngtcp2_crypto_picotls_deconfigure_session(&_context);
				
				if (_context.ptls) {
					ptls_free(_context.ptls);
				}
			}
			
			void Session::set_server_name(std::string_view server_name)
			{
				ptls_set_server_name(_context.ptls, server_name.data(), server_name.size());
			}
			
			std::optional<std::string> Session::server_name() const
			{
				auto name = ptls_get_server_name(_context.ptls);
				
				if (name) {
					return std::string{name};
				}
				else {
					return {};
				}
			}
			
			void Session::set_connection_reference() {
				*ptls_get_data_ptr(_context.ptls) = static_cast<void*>(&_crypto_connection_reference);
			}
			
			ngtcp2_crypto_conn_ref * Session::connection_reference(ptls_t *ptls)
			{
				return static_cast<ngtcp2_crypto_conn_ref *>(*ptls_get_data_ptr(ptls));
			}
			
			std::string Session::cipher_name() const {
				auto cipher = ptls_get_cipher(_context.ptls);
				return cipher->aead->name;
			}
			
			std::string Session::selected_protocol() const {
				auto protocol = ptls_get_negotiated_protocol(_context.ptls);
				
				if (protocol) {
					return protocol;
				} else {
					return {};
				}
			}
			
			void Session::setup_extensions()
			{
				_extensions.push_back({
					.type = UINT16_MAX,
				});
				
				// An optional list of additional extensions to send either in CH or EE, terminated by `type == UINT16_MAX`:
				_context.handshake_properties.additional_extensions = _extensions.data();
			}
		}
	}
}
