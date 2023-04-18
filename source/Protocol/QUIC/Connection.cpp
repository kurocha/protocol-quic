//
//  Connection.cpp
//  This file is part of the "Protocol QUIC" project and released under the .
//
//  Created by Samuel Williams on 17/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Connection.hpp"

#include <chrono>
#include <array>
#include <stdexcept>

namespace Protocol
{
	namespace QUIC
	{
		Timestamp timestamp() {
			return std::chrono::duration_cast<std::chrono::nanoseconds>(
				std::chrono::steady_clock::now().time_since_epoch()
			).count();
		}
		
		Connection::Connection(ngtcp2_conn * connection) : _connection(connection)
		{
		}
		
		Connection::~Connection()
		{
			if (_connection)
				ngtcp2_conn_del(_connection);
		}
		
		void Connection::receive_from(Socket & socket, std::size_t count)
		{
			std::array<std::uint8_t, 1024*64> buffer;
			
			while (count > 0) {
				ECN ecn = ECN::UNSPECIFIED;
				Address remote_address;
				
				auto length = socket.receive_packet(buffer.data(), buffer.size(), remote_address, ecn);
				
				auto const path = ngtcp2_path{
					.local = socket.address(),
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
	}
}
