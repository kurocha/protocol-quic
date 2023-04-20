//
//  ServerContext.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 18/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "ServerContext.hpp"
#include "Session.hpp"

#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif // OPENSSL_VERSION_NUMBER >= 0x30000000L

#include <algorithm>
#include <memory>
#include <array>
#include <stdexcept>

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			int client_hello_callback(ptls_on_client_hello_t *self, ptls_t *ptls, ptls_on_client_hello_parameters_t *params) {
				auto &negotiated_protocols = params->negotiated_protocols;
				
				for (size_t i = 0; i < negotiated_protocols.count; ++i) {
					auto &protocol = negotiated_protocols.list[i];
					
					if (ptls_set_negotiated_protocol(ptls, reinterpret_cast<char *>(protocol.base), protocol.len) != 0) {
						return -1;
					}
					
					return 0;
				}
				
				return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
			}
			
			ptls_on_client_hello_t on_client_hello = {client_hello_callback};
			
			auto ticket_hmac = EVP_sha256();
			
			template <size_t N> void random_bytes(std::array<uint8_t, N> &dest) {
				ptls_openssl_random_bytes(dest.data(), dest.size());
			}
			
			const std::array<uint8_t, 16> &get_ticket_key_name() {
				static std::array<uint8_t, 16> key_name;
				random_bytes(key_name);
				return key_name;
			}
			
			const std::array<uint8_t, 32> &get_ticket_key() {
				static std::array<uint8_t, 32> key;
				random_bytes(key);
				return key;
			}
			
			const std::array<uint8_t, 32> &get_ticket_hmac_key() {
				static std::array<uint8_t, 32> hmac_key;
				random_bytes(hmac_key);
				return hmac_key;
			}
			
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			using HMAC_CTX = EVP_MAC_CTX;
#else  // OPENSSL_VERSION_NUMBER < 0x30000000L
			using HMAC_CTX = ::HMAC_CTX;
#endif // OPENSSL_VERSION_NUMBER < 0x30000000L
			
			int ticket_key_callback(unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
			{
				static const auto &static_key_name = get_ticket_key_name();
				static const auto &static_key = get_ticket_key();
				static const auto &static_hmac_key = get_ticket_hmac_key();
				
				if (enc) {
					ptls_openssl_random_bytes(iv, EVP_MAX_IV_LENGTH);
					
					memcpy(key_name, static_key_name.data(), static_key_name.size());
					
					EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, static_key.data(), iv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
					std::array<OSSL_PARAM, 3> params{
							OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, const_cast<uint8_t *>(static_hmac_key.data()), static_hmac_key.size()),
							OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(EVP_MD_get0_name(ticket_hmac)), 0),
							OSSL_PARAM_construct_end(),
					};
					
					if (!EVP_MAC_CTX_set_params(hctx, params.data())) {
						/* TODO Which value should we return on error? */
						return 0;
					}
#else  // OPENSSL_VERSION_NUMBER < 0x30000000L
					HMAC_Init_ex(hctx, static_hmac_key.data(), static_hmac_key.size(), ticket_hmac, nullptr);
#endif // OPENSSL_VERSION_NUMBER < 0x30000000L
				}
				else {
					if (memcmp(key_name, static_key_name.data(), static_key_name.size()) != 0) {
						return 0;
					}
					
					EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, static_key.data(), iv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
					std::array<OSSL_PARAM, 3> params{
							OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, const_cast<uint8_t *>(static_hmac_key.data()), static_hmac_key.size()),
							OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(EVP_MD_get0_name(ticket_hmac)), 0),
							OSSL_PARAM_construct_end(),
					};
					if (!EVP_MAC_CTX_set_params(hctx, params.data())) {
						/* TODO Which value should we return on error? */
						return 0;
					}
#else  // OPENSSL_VERSION_NUMBER < 0x30000000L
					HMAC_Init_ex(hctx, static_hmac_key.data(), static_hmac_key.size(), ticket_hmac, nullptr);
#endif // OPENSSL_VERSION_NUMBER < 0x30000000L
				}
				
				return 1;
			}
			
			int encrypt_ticket_callback(ptls_encrypt_ticket_t *encrypt_ticket, ptls_t *ptls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src) {
				auto session = Session::get(ptls);
				auto connection = session->connection();
				
				std::uint32_t version;
				
				if (is_encrypt) {
					version = htonl(ngtcp2_conn_get_negotiated_version(connection));
					
					// TODO Replace std::make_unique with
					// std::make_unique_for_overwrite when it is available.
					auto buffer = std::make_unique<uint8_t[]>(src.len + sizeof(version));
					auto pointer = buffer.get();
					
					pointer = std::copy_n(src.base, src.len, pointer);
					pointer = std::copy_n(reinterpret_cast<uint8_t *>(&version), sizeof(version), pointer);

					src.base = buffer.get();
					src.len = pointer - buffer.get();

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
					int result = ptls_openssl_encrypt_ticket_evp(dst, src, ticket_key_callback);
#else  // OPENSSL_VERSION_NUMBER < 0x30000000L
					int result = ptls_openssl_encrypt_ticket(dst, src, ticket_key_callback);
#endif // OPENSSL_VERSION_NUMBER < 0x30000000L
					if (result != 0) {
						return -1;
					}
				}
				else {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
					int result = ptls_openssl_decrypt_ticket_evp(dst, src, ticket_key_callback);
#else  // OPENSSL_VERSION_NUMBER < 0x30000000L
					int result = ptls_openssl_decrypt_ticket(dst, src, ticket_key_callback);
#endif // OPENSSL_VERSION_NUMBER < 0x30000000L
					if (result != 0) {
						return -1;
					}
					
					if (dst->off < sizeof(version)) {
						return -1;
					}
					
					memcpy(&version, dst->base + dst->off - sizeof(version), sizeof(version));
					
					if (ngtcp2_conn_get_client_chosen_version(connection) != ntohl(version)) {
						return -1;
					}
					
					dst->off -= sizeof(version);
				}
				
				return 0;
			}
			
			ptls_encrypt_ticket_t encrypt_ticket = {encrypt_ticket_callback};
			
			ServerContext::ServerContext() : Context()
			{
				if (ngtcp2_crypto_picotls_configure_server_context(&_context) != 0) {
					throw std::runtime_error("ngtcp2_crypto_picotls_configure_client_context failed!");
				}
				
				_context.on_client_hello =  &on_client_hello;
				_context.ticket_lifetime = 86400;
				_context.require_dhe_on_psk = 1;
				_context.server_cipher_preference = 1;
				_context.encrypt_ticket = &encrypt_ticket;
			}
			
			ServerContext::~ServerContext()
			{
			}
			
			void ServerContext::set_require_client_authentication(bool enabled)
			{
				_context.require_client_authentication = enabled;
			}
		}
	}
}
