//
//  Connection.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 17/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Connection.hpp"
#include "Configuration.hpp"
#include "Random.hpp"

#include <chrono>
#include <array>
#include <ngtcp2/ngtcp2.h>
#include <stdexcept>
#include <system_error>

namespace Protocol
{
	namespace QUIC
	{
		Timestamp timestamp() {
			return std::chrono::duration_cast<std::chrono::nanoseconds>(
				std::chrono::steady_clock::now().time_since_epoch()
			).count();
		}
		
		class Ngtcp2ErrorCategory : public std::error_category
		{
		public:
			virtual const char * name() const noexcept override {
				return "ngtcp2";
			}
			
			virtual std::string message(int condition) const override {
				return ngtcp2_strerror(condition);
			}
		};
		
		const std::error_category & ngtcp2_category()
		{
			static Ngtcp2ErrorCategory category;
			
			return category;
		}
		
		void Connection::generate_cid(ngtcp2_cid * cid, std::size_t length)
		{
			assert(length <= NGTCP2_MAX_CIDLEN);
			assert(cid);
			
			cid->datalen = length;
			
			Random::generate_secure(cid->data, cid->datalen);
		}
		
		Connection::Connection(Configuration & configuration, ngtcp2_conn * connection) : _configuration(configuration), _connection(connection)
		{
			ngtcp2_connection_close_error_default(&_last_error);
		}
		
		Connection::~Connection()
		{
			if (_connection)
				ngtcp2_conn_del(_connection);
		}
		
		StreamID Connection::open_bidirectional_stream(void *user_data)
		{
			StreamID stream_id;
			
			auto result = ngtcp2_conn_open_bidi_stream(_connection, &stream_id, user_data);
			
			if (result != 0)
				throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_open_bidi_stream");
			
			return stream_id;
		}
		
		StreamID Connection::open_unidirectional_stream(void *user_data)
		{
			StreamID stream_id;
			
			auto result = ngtcp2_conn_open_uni_stream(_connection, &stream_id, user_data);
			
			if (result != 0)
				throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_open_uni_stream");
			
			return stream_id;
		}
		
		const ngtcp2_cid * Connection::client_initial_dcid()
		{
			return ngtcp2_conn_get_client_initial_dcid(_connection);
		}
		
		std::vector<ngtcp2_cid> Connection::scids()
		{
			auto count = ngtcp2_conn_get_num_scid(_connection);
			std::vector<ngtcp2_cid> result(count);
			
			ngtcp2_conn_get_scid(_connection, result.data());
			
			return result;
		}
		
		int handshake_completed_callback(ngtcp2_conn *conn, void *user_data)
		{
			try {
				reinterpret_cast<Connection*>(user_data)->handshake_completed();
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
		}
		
		void Connection::handshake_completed()
		{
		}
		
		int receive_stream_data_callback(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t size, void *user_data, void *stream_user_data)
		{
			try {
				reinterpret_cast<Connection*>(user_data)->receive_stream_data(flags, stream_id, data, size, stream_user_data);
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
		}
		
		void Connection::receive_stream_data(StreamDataFlags flags, StreamID stream_id, const Byte *buffer, std::size_t length, void * user_data)
		{
		}
		
		void Connection::write_stream_data(StreamID stream_id, const Byte *buffer, std::size_t length, StreamDataFlags flags)
		{
			ngtcp2_path_storage path_storage;
			ngtcp2_path_storage_zero(&path_storage);
			
			ngtcp2_pkt_info packet_info;
			std::array<Byte, 1024*64> packet;
			ngtcp2_ssize written_length = 0;
			
			auto result = ngtcp2_conn_write_stream(_connection, &path_storage.path, &packet_info, packet.data(), packet.size(), &written_length, flags, stream_id, buffer, length, timestamp());
			
			if (result < 0) {
				
			}
		}
		
		void Connection::receive_from(Socket & socket, std::size_t count)
		{
			std::array<std::uint8_t, 1024*64> buffer;
			
			while (count > 0) {
				ECN ecn = ECN::UNSPECIFIED;
				Address remote_address;
				
				auto length = socket.receive_packet(buffer.data(), buffer.size(), remote_address, ecn);
				
				auto const path = ngtcp2_path{
					.local = socket.local_address(),
					.remote = remote_address,
					.user_data = reinterpret_cast<void*>(&socket),
				};
				
				auto packet_info = ngtcp2_pkt_info{
					.ecn = static_cast<std::uint8_t>(ecn),
				};
				
				auto result = ngtcp2_conn_read_pkt(_connection, &path, &packet_info, buffer.data(), length, timestamp());
				
				if (result < 0) {
					if (!_last_error.error_code) {
						if (result == NGTCP2_ERR_CRYPTO) {
							ngtcp2_connection_close_error_set_transport_error_tls_alert(&_last_error, ngtcp2_conn_get_tls_alert(_connection), nullptr, 0);
						} else {
							ngtcp2_connection_close_error_set_transport_error_liberr(&_last_error, result, nullptr, 0);
						}
					}
					
					this->disconnect();
					
					throw std::runtime_error("ngtcp2_conn_read_pkt");
				}
				
				count -= 1;
			}
		}
		
		void Connection::handle_error()
		{
			if (!_connection || ngtcp2_conn_is_in_closing_period(_connection) || ngtcp2_conn_is_in_draining_period(_connection)) {
				return;
			}
			
			std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buffer;
			ngtcp2_path_storage path_storage;
			ngtcp2_path_storage_zero(&path_storage);
			
			ngtcp2_pkt_info packet_info;
			
			auto result = ngtcp2_conn_write_connection_close(_connection, &path_storage.path, &packet_info, buffer.data(), buffer.size(), &_last_error, timestamp());
			
			if (result < 0) {
				throw std::runtime_error("ngtcp2_conn_write_connection_close");
			}
			
			if (result == 0) {
				// Nothing to do:
				return;
			}
			
			Socket & socket = *static_cast<Socket *>(path_storage.path.user_data);
			socket.send_packet(buffer.data(), result, path_storage.path.remote, static_cast<ECN>(packet_info.ecn));
		}
		
		void Connection::disconnect()
		{
			if (_connection) {
				ngtcp2_conn_del(_connection);
				_connection = nullptr;
			}
		}
		
		void random_callback(std::uint8_t *dest, std::size_t size, const ngtcp2_rand_ctx *context)
		{
			auto & random = *reinterpret_cast<Random*>(context->native_handle);
			random.generate(dest, size);
		}
		
		int get_new_connection_id_callback(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data)
		{
			auto & connection = *reinterpret_cast<Connection*>(user_data);
			
			try {
				connection.generate_connection_id(cid, cidlen, token);
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		void Connection::setup(ngtcp2_callbacks *callbacks, ngtcp2_settings *settings, ngtcp2_transport_params *params)
		{
			ngtcp2_settings_default(settings);
			ngtcp2_transport_params_default(params);
			
			// Setup the random data generator:
			settings->rand_ctx.native_handle = reinterpret_cast<void*>(&_random);
			callbacks->rand = random_callback;
			
			callbacks->client_initial = ngtcp2_crypto_client_initial_cb;
			callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
			callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
			callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
			callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
			callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
			callbacks->get_new_connection_id = get_new_connection_id_callback;
			callbacks->update_key = ngtcp2_crypto_update_key_cb;
			callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
			callbacks->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
			callbacks->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
			callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
			
			callbacks->handshake_completed = handshake_completed_callback;
			callbacks->recv_stream_data = receive_stream_data_callback;
			
			settings->initial_ts = timestamp();
		}
		
		void Connection::generate_connection_id(ngtcp2_cid *cid, std::size_t cidlen, uint8_t *token)
		{
			Random::generate_secure(cid->data, cidlen);
			cid->datalen = cidlen;
			
			auto &static_secret = _configuration.static_secret;
			
			if (ngtcp2_crypto_generate_stateless_reset_token(token, static_secret.data(), static_secret.size(), cid) != 0) {
				throw std::runtime_error("Failed to generate stateless reset token!");
			}
		}
		
		void Connection::set_last_error(int result)
		{
			if (!_last_error.error_code) {
				if (result == NGTCP2_ERR_CRYPTO) {
					ngtcp2_connection_close_error_set_transport_error_tls_alert(&_last_error, ngtcp2_conn_get_tls_alert(_connection), nullptr, 0);
				} else {
					ngtcp2_connection_close_error_set_transport_error_liberr(&_last_error, result, nullptr, 0);
				}
			}
		}
	}
}