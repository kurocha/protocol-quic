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
#include "picotls.h"

#include <chrono>
#include <array>
#include <ngtcp2/ngtcp2.h>
#include <stdexcept>
#include <system_error>

#include <iostream>
#include <stdio.h>

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
			
			Random::generate_secure(cid->data, length);
			cid->datalen = length;
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
		
		Stream *Connection::create_stream(StreamID stream_id)
		{
			auto [iterator, inserted] = _streams.emplace(
				stream_id,
				std::make_unique<Stream>(stream_id)
			);
			
			if (!inserted) {
				throw std::runtime_error("Stream already exists!");
			}
			
			ngtcp2_conn_set_stream_user_data(_connection, stream_id, iterator->second.get());
			
			return iterator->second.get();
		}
		
		Stream* Connection::open_bidirectional_stream()
		{
			StreamID stream_id;
			
			auto result = ngtcp2_conn_open_bidi_stream(_connection, &stream_id, nullptr);
			
			if (result != 0)
				throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_open_bidi_stream");
			
			return create_stream(stream_id);
		}
		
		Stream* Connection::open_unidirectional_stream()
		{
			StreamID stream_id;
			
			auto result = ngtcp2_conn_open_uni_stream(_connection, &stream_id, nullptr);
			
			if (result != 0)
				throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_open_uni_stream");
			
			return create_stream(stream_id);
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
			
			return 0;
		}
		
		void Connection::handshake_completed()
		{
			std::cerr << "*** handshake_completed ***" << std::endl;
		}
		
		int receive_stream_data_callback(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t size, void *user_data, void *stream_user_data)
		{
			std::cerr << "receive_stream_data_callback: " << stream_id << std::endl;
			
			auto stream = reinterpret_cast<Stream*>(stream_user_data);
			
			try {
				stream->input_buffer().append(data, size);
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		int acked_stream_data_offset_callback(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data)
		{
			std::cerr << "acked_stream_data_offset_callback: " << stream_id << std::endl;
			
			auto stream = reinterpret_cast<Stream*>(stream_user_data);
			
			try {
				stream->output_buffer().acknowledge(datalen);
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		void Connection::write_packets()
		{
			std::array<Byte, 1024*64> packet;
			ngtcp2_path_storage path_storage;
			ngtcp2_path_storage_zero(&path_storage);
			ngtcp2_pkt_info packet_info;
			ngtcp2_ssize written_length = 0;
			StreamDataFlags flags = 0;
			
			auto result = ngtcp2_conn_write_stream(_connection, &path_storage.path, &packet_info, packet.data(), packet.size(), &written_length, flags, -1, nullptr, 0, timestamp());
			
			if (result < 0) {
				throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_write_stream");
			}
			
			if (result > 0) {
				auto & socket = *reinterpret_cast<Socket*>(path_storage.path.user_data);
				
				auto size = socket.send_packet(packet.data(), result, path_storage.path.remote, static_cast<ECN>(packet_info.ecn));
				
				if (size != result) {
					throw std::runtime_error("send_packet failed");
				}
			}
			
			for (auto & [stream_id, stream] : _streams) {
				write_packets(stream.get());
			}
		}
		
		void Connection::write_packets(Stream * stream)
		{
			ngtcp2_path_storage path_storage;
			ngtcp2_path_storage_zero(&path_storage);
			ngtcp2_pkt_info packet_info;
			ngtcp2_ssize written_length = 0;
			
			std::array<Byte, 1024*64> packet;
			
			StreamDataFlags flags = 0;
			if (stream->output_buffer().closed())
				flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
			
			auto chunks = stream->output_buffer().chunks();
			
			auto result = ngtcp2_conn_writev_stream(_connection, &path_storage.path, &packet_info, packet.data(), packet.size(), &written_length, flags, stream->stream_id(), chunks.data(), chunks.size(), timestamp());
			
			if (result < 0) {
				throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_write_stream");
			}
			
			if (result > 0) {
				auto & socket = *reinterpret_cast<Socket*>(path_storage.path.user_data);
				
				auto size = socket.send_packet(packet.data(), result, path_storage.path.remote, static_cast<ECN>(packet_info.ecn));
				
				if (size > 0)
					stream->output_buffer().increment(size);
			}
		}
		
		void Connection::read_packets(Socket & socket, std::size_t count)
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
				
				std::cerr << *this << " read_packets: " << path.local << " -> " << path.remote << std::endl;
				
				auto packet_info = ngtcp2_pkt_info{
					.ecn = static_cast<std::uint8_t>(ecn),
				};
				
				auto result = ngtcp2_conn_read_pkt(_connection, &path, &packet_info, buffer.data(), length, timestamp());
				
				if (result < 0) {
					set_last_error(result);
					
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
			std::cerr << "get_new_connection_id_callback" << std::endl;
			
			auto & connection = *reinterpret_cast<Connection*>(user_data);
			
			try {
				connection.generate_connection_id(cid, cidlen, token);
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		void log_printf(void *user_data, const char *fmt, ...) {
			va_list ap;
			(void)user_data;
			char buffer[1024*4];
			
			auto connection = reinterpret_cast<Connection*>(user_data);
			
			va_start(ap, fmt);
			vsnprintf(buffer, sizeof(buffer), fmt, ap);
			va_end(ap);
			
			std::cerr << *connection << " ngtcp2: " << buffer << std::endl;
		}
		
		void Connection::setup(ngtcp2_callbacks *callbacks, ngtcp2_settings *settings, ngtcp2_transport_params *params)
		{
			// Setup the random data generator:
			settings->rand_ctx.native_handle = reinterpret_cast<void*>(&_random);
			callbacks->rand = random_callback;
			
			callbacks->client_initial = ngtcp2_crypto_client_initial_cb;
			callbacks->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
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
			callbacks->acked_stream_data_offset = acked_stream_data_offset_callback;
			
			settings->initial_ts = timestamp();
			settings->log_printf = log_printf;
			
			// The default of 2 is apparently invalid:
			params->active_connection_id_limit = 7;
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
			std::cerr << *this << " ngtcp2: " << ngtcp2_strerror(result) << std::endl;
			
			if (!_last_error.error_code) {
				if (result == NGTCP2_ERR_CRYPTO) {
					ngtcp2_connection_close_error_set_transport_error_tls_alert(&_last_error, ngtcp2_conn_get_tls_alert(_connection), nullptr, 0);
				} else {
					ngtcp2_connection_close_error_set_transport_error_liberr(&_last_error, result, nullptr, 0);
				}
			}
		}
		
		void Connection::print(std::ostream & output) const
		{
			output << "<Connection@" << this << ">";
		}
		
		std::ostream & operator<<(std::ostream & output, const Connection & connection)
		{
			connection.print(output);
			
			return output;
		}
	}
}