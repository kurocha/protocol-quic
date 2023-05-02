//
//  Socket.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 8/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#include "Socket.hpp"
#include "Defer.hpp"

#include <cstring>
#include <system_error>
#include <iostream>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#endif

#include <Scheduler/Monitor.hpp>

namespace Protocol
{
	namespace QUIC
	{
		enum {DEBUG = 0};
		
		int set_receive_ecn(int descriptor, int family) {
			int tos = 1;
			
			switch (family) {
			case AF_INET:
				return setsockopt(descriptor, IPPROTO_IP, IP_RECVTOS, &tos, static_cast<socklen_t>(sizeof(tos)));
			case AF_INET6:
				return setsockopt(descriptor, IPPROTO_IPV6, IPV6_RECVTCLASS, &tos, static_cast<socklen_t>(sizeof(tos)));
			}
			
			return 0;
		}
		
		// Supported on Linux.
		int set_ip_mtu_discover(int descriptor, int family) {
#if defined(IP_MTU_DISCOVER) && defined(IPV6_MTU_DISCOVER)
			int value;
			
			switch (family) {
			case AF_INET:
				value = IP_PMTUDISC_DO;
				return setsockopt(descriptor, IPPROTO_IP, IP_MTU_DISCOVER, &value, static_cast<socklen_t>(sizeof(value)));
			case AF_INET6:
				value = IPV6_PMTUDISC_DO;
				return setsockopt(descriptor, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &value, static_cast<socklen_t>(sizeof(value)));
			}
#endif
			
			return 0;
		}
		
		// Supported on BSD.
		int set_ip_dontfrag(int descriptor, int family) {
#if defined(IP_DONTFRAG) && defined(IPV6_DONTFRAG)
			int value = 1;
			
			switch (family) {
			case AF_INET:
				return setsockopt(descriptor, IPPROTO_IP, IP_DONTFRAG, &value, static_cast<socklen_t>(sizeof(value)));
			case AF_INET6:
				return setsockopt(descriptor, IPPROTO_IPV6, IPV6_DONTFRAG, &value, static_cast<socklen_t>(sizeof(value)));
			}
#endif
			
			return 0;
		}
		
		int socket_nonblocking(int domain, int type, int protocol)
		{
#ifdef SOCK_NONBLOCK
			int descriptor = socket(domain, type|SOCK_NONBLOCK, protocol);
#else
			int descriptor = socket(domain, type, protocol);
			fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL, 0)|O_NONBLOCK);
#endif
			
			if (descriptor < 0) {
				throw std::system_error(errno, std::generic_category(), "socket");
			}
			
			return descriptor;
		}
		
		Socket::Socket(int domain, int type, int protocol)
		{
			_descriptor = socket_nonblocking(domain, SOCK_DGRAM, 0);
			
			if (_descriptor < 0) {
				throw std::system_error(errno, std::generic_category(), "socket");
			}
			
			set_receive_ecn(_descriptor, domain);
			set_ip_mtu_discover(_descriptor, domain);
			set_ip_dontfrag(_descriptor, domain);
		}
		
		void Socket::close() {
				if (_descriptor >= 0) {
					::close(_descriptor);
					
					_descriptor = -1;
				}
			}
		
		Socket::~Socket()
		{
			std::cerr << *this << " Socket::~Socket()" << std::endl;
			close();
		}
		
		Socket::Socket(Socket && other)
		{
			_descriptor = other._descriptor;
			_local_address = other._local_address;
			_remote_address = other._remote_address;
			other._descriptor = -1;
		}
		
		Socket & Socket::operator=(Socket && other)
		{
			_descriptor = other._descriptor;
			_local_address = other._local_address;
			_remote_address = other._remote_address;
			other._descriptor = -1;
			return *this;
		}
		
		const Address & Socket::local_address() const
		{
			if (!_local_address) {
				sockaddr_storage storage;
				
				sockaddr * data = reinterpret_cast<sockaddr *>(&storage);
				socklen_t size = sizeof(storage);
				auto result = ::getsockname(_descriptor, data, &size);
				
				if (result == -1)
					throw std::system_error(errno, std::generic_category(), "getsockname");
				
				_local_address.set(data, size);
			}
			
			return _local_address;
		}
		
		const Address & Socket::remote_address() const
		{
			if (!_remote_address) {
				sockaddr_storage storage;
				sockaddr * data = reinterpret_cast<sockaddr *>(&storage);
				socklen_t size = sizeof(storage);
				
				auto result = ::getpeername(_descriptor, data, &size);
				
				if (result == -1)
					throw std::system_error(errno, std::generic_category(), "getpeername");
				
				_remote_address.set(data, size);
			}
			
			return _remote_address;
		}
		
		bool Socket::bind(const Address & address)
		{
			if (::bind(_descriptor, &address.data.sa, address.length) < 0) {
				return false;
			}
			
			std::cerr << *this << " bind address=" << address << std::endl;
			
			_local_address = address;
			return true;
		}
		
		bool Socket::connect(const Address & address)
		{
			if (::connect(_descriptor, &address.data.sa, address.length) < 0) {
				return false;
			}
			
			std::cerr << *this << " connect address=" << address << std::endl;
			
			_remote_address = address;
			return true;
		}
		
		ECN read_ecn(const std::uint8_t *data)
		{
			return static_cast<ECN>(data[0] & 0x03);
		}
		
		ECN get_ecn(msghdr * message, int family) {
			switch (family) {
			case AF_INET:
				for (auto cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS && cmsg->cmsg_len) {
						return read_ecn(CMSG_DATA(cmsg));
					}
				}
				break;
			case AF_INET6:
				for (auto cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS && cmsg->cmsg_len) {
						return read_ecn(CMSG_DATA(cmsg));
					}
				}
				break;
			}
			
			return ECN::UNSPECIFIED;
		}
		
		int set_ecn(int descriptor, int family, ECN ecn) {
			int tos = static_cast<unsigned int>(ecn);
			
			switch (family) {
			case AF_INET:
				return setsockopt(descriptor, IPPROTO_IP, IP_TOS, &tos, static_cast<socklen_t>(sizeof(ecn)));
			case AF_INET6:
				return setsockopt(descriptor, IPPROTO_IPV6, IPV6_TCLASS, &tos, static_cast<socklen_t>(sizeof(ecn)));
			}
			
			return 0;
		}
		
		size_t Socket::send_packet(const void * data, std::size_t size, const Destination & destination, ECN ecn, const Timestamp * timeout)
		{
			if (DEBUG) std::cerr << *this << " send_packet " << size << " bytes to " << destination << std::endl;
			
			iovec iov{
				.iov_base = const_cast<void *>(data),
				.iov_len = size
			};
			
			msghdr message{
				.msg_name = nullptr,
				.msg_namelen = 0,
				.msg_iov = &iov,
				.msg_iovlen = 1
			};
			
			if (_remote_address) {
				// Already connected...
				assert(_remote_address == destination);
			}
			else {
				// Not connected, so we need to set the destination address:
				message.msg_name = const_cast<sockaddr *>(destination.addr);
				message.msg_namelen = destination.addrlen;
			}
			
			if (ecn != _ecn) {
				set_ecn(_descriptor, destination.addr->sa_family, ecn);
			}
			
			ssize_t result;
			Scheduler::Monitor monitor(_descriptor);
			
			do {
				result = sendmsg(_descriptor, &message, 0);
				
				if (result == -1) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						if (!monitor.wait_writable(timeout)) {
							return 0;
						}
					} else if (errno == EINTR) {
						// ignore
					} else {
						throw std::system_error(errno, std::generic_category(), "sendmsg");
					}
				}
			} while (result == -1);
			
			return result;
		}
		
		size_t Socket::receive_packet(void *data, std::size_t size, Address &address, ECN &ecn, const Timestamp * timeout)
		{
			iovec iov = {
				.iov_base = data,
				.iov_len = size
			};
			
			uint8_t message_control[CMSG_SPACE(sizeof(uint8_t))];
			
			msghdr message = {
				// Provide the address data pointer / length:
				.msg_name = &address.data,
				.msg_namelen = sizeof(address.data),
				
				// Provide the data buffer io vectors:
				.msg_iov = &iov,
				.msg_iovlen = 1,
				
				// Provide the message control buffer (for reading the ecn):
				.msg_control = message_control,
				.msg_controllen = sizeof(message_control)
			};
			
			ssize_t result;
			
			Scheduler::Monitor monitor(_descriptor);
			
			do {
				result = recvmsg(_descriptor, &message, 0);
				
				if (result == -1) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						if (!monitor.wait_readable(timeout)) {
							return 0;
						}
					} else if (errno == EINTR) {
						// ignore
					} else {
						throw std::system_error(errno, std::generic_category(), "recvmsg");
					}
				}
			} while (result == -1);
			
			// Read the ECN from the message control buffer:
			_ecn = ecn = get_ecn(&message, address.data.sa.sa_family);
			
			// Update the address with the actual length:
			address.length = message.msg_namelen;
			
			if (DEBUG) std::cerr << *this << " receive_packet " << result << " bytes from " << address << std::endl;
			
			return result;
		}
		
		std::ostream & operator<<(std::ostream & output, const Socket & socket)
		{
			output << "<Socket@" << &socket;
			
			if (!socket.annotation().empty())
				output << " " << socket.annotation();
			
			output << " descriptor=" << socket.descriptor() << ">";
			
			return output;
		}
	}
}
