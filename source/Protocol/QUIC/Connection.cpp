//
//  Connection.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 17/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Connection.hpp"
#include "BufferedStream.hpp"
#include "Configuration.hpp"
#include "Random.hpp"

#include <Time/Interval.hpp>

#include <chrono>
#include <array>
#include <ngtcp2/ngtcp2.h>
#include <stdexcept>
#include <system_error>

#include <iostream>
#include <iomanip>
#include <stdio.h>

namespace Protocol
{
	namespace QUIC
	{
		ngtcp2_tstamp timestamp() {
			return Timestamp().as_nanoseconds();
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
		
		void Connection::close()
		{
			std::array<Byte, 1024*64> packet;
			ngtcp2_path_storage path_storage;
			ngtcp2_path_storage_zero(&path_storage);
			ngtcp2_pkt_info packet_info;
			
			auto result = ngtcp2_conn_write_connection_close(_connection, &path_storage.path, &packet_info, packet.data(), packet.size(), &_last_error, timestamp());
			
			if (result < 0) {
				throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_write_connection_close");
			}
			
			auto *socket = reinterpret_cast<Socket*>(path_storage.path.user_data);
			assert(socket);
			
			auto expiry_timeout = this->expiry_timeout();
			socket->send_packet(packet.data(), result, path_storage.path.remote, ECN(packet_info.ecn), extract_optional(expiry_timeout));
			
			socket->close();
		}
		
		Stream *Connection::open_stream(StreamID stream_id)
		{
			auto [iterator, inserted] = _streams.emplace(stream_id, create_stream(stream_id));
			
			if (!inserted) {
				throw std::runtime_error("Stream already exists!");
			}
			
			ngtcp2_conn_set_stream_user_data(_connection, stream_id, iterator->second);
			
			return iterator->second;
		}
		
		Stream* Connection::open_bidirectional_stream()
		{
			StreamID stream_id;
			
			auto result = ngtcp2_conn_open_bidi_stream(_connection, &stream_id, nullptr);
			
			if (result != 0)
				throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_open_bidi_stream");
			
			return open_stream(stream_id);
		}
		
		Stream* Connection::open_unidirectional_stream()
		{
			StreamID stream_id;
			
			auto result = ngtcp2_conn_open_uni_stream(_connection, &stream_id, nullptr);
			
			if (result != 0)
				throw std::system_error(result, ngtcp2_category(), "ngtcp2_conn_open_uni_stream");
			
			return open_stream(stream_id);
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
		
		std::optional<Timestamp> Connection::expiry_timeout() {
			auto maybe_expiry = ngtcp2_conn_get_expiry(_connection);
			
			if (maybe_expiry != UINT64_MAX) {
				return Timestamp::from_nanoseconds(maybe_expiry);
			}
			
			return std::nullopt;
		}
		
		Time::Duration Connection::close_duration() {
			auto probe_timeout = Time::Interval::from_nanoseconds(ngtcp2_conn_get_pto(_connection));
			
			return Time::Duration(probe_timeout * 3);
		}
		
		int handshake_completed_callback(ngtcp2_conn *conn, void *user_data)
		{
			Connection *connection = reinterpret_cast<Connection*>(user_data);
			
			try {
				connection->handshake_completed();
			} catch (std::exception & error) {
				std::cerr << "handshake_completed_callback: " << error.what() << std::endl;
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		void Connection::handshake_completed()
		{
		}
		
		int extend_max_local_streams_bidi_callback(ngtcp2_conn *conn, uint64_t max_streams, void *user_data)
		{
			Connection *connection = reinterpret_cast<Connection*>(user_data);
			
			try {
				connection->extend_maximum_local_bidirectional_streams(max_streams);
			} catch (std::exception & error) {
				std::cerr << "extend_max_local_streams_bidi_callback: " << error.what() << std::endl;
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		void Connection::extend_maximum_local_bidirectional_streams(std::uint64_t maximum_streams)
		{
		}
		
		int extend_max_local_streams_uni_callback(ngtcp2_conn *conn, uint64_t max_streams, void *user_data)
		{
			Connection *connection = reinterpret_cast<Connection*>(user_data);
			
			try {
				connection->extend_maximum_local_unidirectional_streams(max_streams);
			} catch (std::exception & error) {
				std::cerr << "extend_max_local_streams_uni_callback: " << error.what() << std::endl;
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		void Connection::extend_maximum_local_unidirectional_streams(std::uint64_t maximum_streams)
		{
		}
		
		int stream_open_callback(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
		{
			Connection *connection = reinterpret_cast<Connection*>(user_data);
			
			try {
				connection->stream_open(stream_id);
			} catch (std::exception & error) {
				std::cerr << "stream_open_callback: " << error.what() << std::endl;
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		Stream* Connection::stream_open(StreamID stream_id)
		{
			return open_stream(stream_id);
		}
		
		int stream_close_callback(ngtcp2_conn *conn, uint32_t flags, StreamID stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data)
		{
			Connection *connection = reinterpret_cast<Connection*>(user_data);
			Stream *stream = reinterpret_cast<Stream*>(stream_user_data);
			
			try {
				connection->stream_close(stream, flags, app_error_code);
			} catch (std::exception & error) {
				std::cerr << "stream_close_callback: " << error.what() << std::endl;
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		void Connection::stream_close(Stream * stream, int32_t flags, uint64_t error_code)
		{
			auto iterator = _streams.find(stream->stream_id());
			
			if (iterator == _streams.end()) {
				throw std::runtime_error("stream_close: stream not found");
			}
			
			iterator->second->close(flags, error_code);
			_streams.erase(iterator);
		}
		
		int stream_reset_callback(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size, uint64_t app_error_code, void *user_data, void *stream_user_data)
		{
			Connection *connection = reinterpret_cast<Connection*>(user_data);
			Stream *stream = reinterpret_cast<Stream*>(stream_user_data);

			try {
				connection->stream_reset(stream, final_size, app_error_code);
			} catch (std::exception & error) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		void Connection::stream_reset(Stream * stream, std::size_t final_size, std::uint64_t error_code)
		{
			auto iterator = _streams.find(stream->stream_id());
			
			if (iterator == _streams.end()) {
				throw std::runtime_error("stream_reset: stream not found");
			}
			
			iterator->second->reset(final_size, error_code);
			_streams.erase(iterator);
		}
		
		void Connection::remove_stream(StreamID stream_id)
		{
			_streams.erase(stream_id);
		}
		
		int receive_stream_data_callback(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t size, void *user_data, void *stream_user_data)
		{
			auto stream = reinterpret_cast<Stream*>(stream_user_data);
			
			try {
				stream->receive_data(offset, data, size, flags);
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		int stream_stop_sending_callback(ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data)
		{
			auto stream = reinterpret_cast<Stream*>(stream_user_data);
			
			try {
				stream->stop_sending(app_error_code);
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		int extend_max_stream_data_callback(ngtcp2_conn *conn, int64_t stream_id, uint64_t max_data, void *user_data, void *stream_user_data)
		{
			auto stream = reinterpret_cast<Stream*>(stream_user_data);
			
			try {
				stream->extend_maximum_data(max_data);
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		int acked_stream_data_offset_callback(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data)
		{
			auto stream = reinterpret_cast<Stream*>(stream_user_data);
			
			try {
				stream->acknowledge_data(datalen);
			} catch (...) {
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}
			
			return 0;
		}
		
		Connection::Status Connection::send_packets()
		{
			std::array<Byte, 1024*64> packet;
			ngtcp2_path_storage path_storage;
			ngtcp2_path_storage_zero(&path_storage);
			ngtcp2_pkt_info packet_info;
			ngtcp2_ssize written_length = 0;
			StreamDataFlags flags = 0;
			
			while (true) {
				auto result = ngtcp2_conn_write_stream(_connection, &path_storage.path, &packet_info, packet.data(), packet.size(), &written_length, flags, -1, nullptr, 0, timestamp());
				
				if (result < 0) return Status(result);
				
				if (result > 0) {
					auto timeout = expiry_timeout();
					auto & socket = *reinterpret_cast<Socket*>(path_storage.path.user_data);
					
					auto size = socket.send_packet(packet.data(), result, path_storage.path.remote, static_cast<ECN>(packet_info.ecn), extract_optional(timeout));
					
					if (!size) {
						handle_expiry();
					}
					
					if (size != result) {
						throw std::runtime_error("send_packet failed");
					}
				}
				else {
					break;
				}
			}
			
			for (auto & [stream_id, stream] : _streams) {
				stream->send_data();
			}
			
			return Status::OK;
		}
		
		Connection::Status Connection::receive_packets(const ngtcp2_path & path, Socket & socket, std::size_t count)
		{
			std::array<std::uint8_t, 1024*64> buffer;
			
			while (count > 0) {
				ECN ecn = ECN::UNSPECIFIED;
				Address remote_address;
				auto timeout = expiry_timeout();
				
				auto size = socket.receive_packet(buffer.data(), buffer.size(), remote_address, ecn, extract_optional(timeout));
				
				if (!size) {
					handle_expiry();
					
					return Status::DRAINING;
				}
				
				auto packet_info = ngtcp2_pkt_info{
					.ecn = static_cast<std::uint8_t>(ecn),
				};
				
				auto result = ngtcp2_conn_read_pkt(_connection, &path, &packet_info, buffer.data(), size, timestamp());
				
				if (result < 0) {
					set_last_error(result);
					disconnect();
					
					return Status(result);
				}
				
				count -= 1;
			}
			
			return Status::OK;
		}
		
		Connection::Status Connection::receive_packets(const ngtcp2_path & path, std::size_t count)
		{
			auto & socket = *reinterpret_cast<Socket*>(path.user_data);
			
			if (socket)
				return receive_packets(path, socket, count);
			else
				return Status::CLOSING;
		}
		
		void Connection::handle_expiry()
		{
			auto now = timestamp();
			auto result = ngtcp2_conn_handle_expiry(_connection, now);
			
			if (result != 0) {
				ngtcp2_connection_close_error_set_transport_error_liberr(&_last_error, result, nullptr, 0);
				
				disconnect();
			}
			else {
				send_packets();
			}
		}
		
		void Connection::disconnect()
		{
			close();
			
			for (auto & [stream_id, stream] : _streams) {
				stream->disconnect();
			}
			
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
			_configuration.setup(settings, params);
			
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
			
			callbacks->extend_max_local_streams_bidi = extend_max_local_streams_bidi_callback;
			callbacks->extend_max_local_streams_uni = extend_max_local_streams_uni_callback;
			
			callbacks->stream_open = stream_open_callback;
			callbacks->stream_close = stream_close_callback;
			callbacks->stream_reset = stream_reset_callback;
			callbacks->stream_stop_sending = stream_stop_sending_callback;
			callbacks->extend_max_stream_data = extend_max_stream_data_callback;
			
			callbacks->recv_stream_data = receive_stream_data_callback;
			callbacks->acked_stream_data_offset = acked_stream_data_offset_callback;
			
			settings->initial_ts = timestamp();
			// settings->log_printf = log_printf;
			
			params->initial_max_stream_data_bidi_local = 128 * 1024;
			params->initial_max_stream_data_bidi_remote = 128 * 1024;
			params->initial_max_stream_data_uni = 128 * 1024;
			params->initial_max_data = 1024 * 1024;
			
			params->initial_max_streams_bidi = 3;
			params->initial_max_streams_uni = 3;
			
			// The default of 2 is apparently invalid:
			params->active_connection_id_limit = 7;
		}
		
		void Connection::generate_connection_id(ngtcp2_cid *cid, std::size_t cidlen, uint8_t *token)
		{
			generate_cid(cid, cidlen);
			
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