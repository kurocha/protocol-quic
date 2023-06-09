//
//  Context.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 18/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Context.hpp"
#include "picotls.h"

#include <openssl/pem.h>
#include <stdexcept>
#include <string>

namespace Protocol
{
	namespace QUIC
	{
		namespace TLS
		{
			Protocols::Protocols(const std::vector<std::string> & protocols)
			{
				for (auto & protocol : protocols) {
					ptls_iovec_t name = {
						.base = new uint8_t[protocol.size()],
						.len = protocol.size(),
					};
					
					memcpy(name.base, protocol.data(), protocol.size());
					
					names.push_back(name);
				}
			}
			
			Protocols::~Protocols()
			{
				for (auto & name : names) {
					delete[] name.base;
				}
			}
			
			ptls_key_exchange_algorithm_t *DEFAULT_KEY_EXCHANGES[] = {
				&ptls_openssl_x25519,
				&ptls_openssl_secp256r1,
				&ptls_openssl_secp384r1,
				&ptls_openssl_secp521r1,
				nullptr,
			};
			
			ptls_cipher_suite_t *DEFAULT_CIPHER_SUITS[] = {
				&ptls_openssl_aes128gcmsha256,
				&ptls_openssl_aes256gcmsha384,
				&ptls_openssl_chacha20poly1305sha256,
				nullptr,
			};
			
			Context::Context() : _context{.random_bytes = ptls_openssl_random_bytes, .get_time = &ptls_get_time, .key_exchanges = DEFAULT_KEY_EXCHANGES, .cipher_suites = DEFAULT_CIPHER_SUITS, .require_dhe_on_psk = 1}, _sign_certificate{}
			{
			}
			
			Context::~Context()
			{
				if (_sign_certificate.key) {
					ptls_openssl_dispose_sign_certificate(&_sign_certificate);
				}
				
				for (size_t i = 0; i < _context.certificates.count; ++i) {
					free(_context.certificates.list[i].base);
				}
				
				free(_context.certificates.list);
			}
			
			void Context::set_keylog(bool enabled)
			{
			}
			
			void Context::load_certificate_file(const char * path)
			{
				if (ptls_load_certificates(&_context, path) != 0) {
					throw std::runtime_error(std::string("Could not load certificate file ") + path);
				}
			}
			
			template <typename Callback>
			struct Defer {
				Callback _callback;
				
				Defer(Callback callback) : _callback(callback) {}
				~Defer() {_callback();}
			};
			
			template <typename Callback>
			Defer<Callback> defer(Callback callback) {
				return Defer<Callback>(callback);
			}
			
			void Context::load_private_key_file(const char * path)
			{
				auto file = fopen(path, "rb");
				if (file == nullptr) {
					throw std::runtime_error(std::string("Could not open private key file ") + path);
				}
				
				auto close_file = defer([&]{fclose(file);});
				
				auto private_key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
				if (private_key == nullptr) {
					throw std::runtime_error(std::string("Could not read private key file ") + path);
				}
				
				auto free_private_key = defer([&]{EVP_PKEY_free(private_key);});
				
				if (ptls_openssl_init_sign_certificate(&_sign_certificate, private_key) != 0) {
					throw std::runtime_error(std::string("Could not initialize sign certificate ") + path);
				}
				
				_context.sign_certificate = &_sign_certificate.super;
			}
		}
	}
}
