//
//  Socket.cpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 8/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#define __APPLE_USE_RFC_3542

#include "Socket.hpp"
#include "Defer.hpp"

#include <cstring>
#include <system_error>

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
		std::string Address::to_string() const
		{
			char buffer[NI_MAXHOST];
			
			if (getnameinfo(&data.sa, length, buffer, sizeof(buffer), nullptr, 0, NI_NUMERICHOST) != 0) {
				throw std::runtime_error("getnameinfo");
			}
			
			return buffer;
		}
		
		std::optional<Address> Address::extract(msghdr *message, int family)
		{
			if (family == AF_INET) {
				for (auto cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
						auto pktinfo = reinterpret_cast<in_pktinfo *>(CMSG_DATA(cmsg));
						Address address;
						address.length = sizeof(address.data.in);
						address.data.in.sin_family = AF_INET;
						address.data.in.sin_addr = pktinfo->ipi_addr;
						return address;
					}
				}
			}
			else if (family == AF_INET6) {
				for (auto cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
						auto pktinfo = reinterpret_cast<in6_pktinfo *>(CMSG_DATA(cmsg));
						Address address;
						address.length = sizeof(address.data.in6);
						address.data.in6.sin6_family = AF_INET6;
						address.data.in6.sin6_addr = pktinfo->ipi6_addr;
						return address;
					}
				}
			}
			
			return {};
		}
		
		std::vector<Address> Address::resolve(const char * host, const char * service, int family, int type, int flags)
		{
			std::vector<Address> addresses;
			
			addrinfo hints;
			std::memset(&hints, 0, sizeof(hints));
			
			hints.ai_family = family;
			hints.ai_socktype = type;
			hints.ai_flags = flags;
			
			addrinfo * result = nullptr;
			
			if (getaddrinfo(host, service, &hints, &result) != 0) {
				throw std::runtime_error("getaddrinfo");
			}
			
			Defer free_result([&]{
				freeaddrinfo(result);
			});
			
			for (auto iterator = result; iterator; iterator = iterator->ai_next) {
				addresses.emplace_back(iterator->ai_addr, iterator->ai_addrlen);
			}
			
			return addresses;
		}
		
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
		
		Socket::~Socket()
		{
			if (_descriptor >= 0) {
				::close(_descriptor);
			}
		}
		
		Socket::Socket(Socket && other)
		{
			_descriptor = other._descriptor;
			_address = other._address;
			other._descriptor = -1;
		}
		
		Socket & Socket::operator=(Socket && other)
		{
			_descriptor = other._descriptor;
			_address = other._address;
			other._descriptor = -1;
			return *this;
		}
		
		void Socket::bind(const Address & address)
		{
			if (::bind(_descriptor, &address.data.sa, address.length) < 0) {
				throw std::system_error(errno, std::generic_category(), "bind");
			}
			
			_address = address;
		}
		
		void Socket::connect(const Address & address)
		{
			if (::connect(_descriptor, &address.data.sa, address.length) < 0) {
				throw std::system_error(errno, std::generic_category(), "connect");
			}
			
			_address = address;
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
		
		size_t Socket::send_packet(const void * data, std::size_t size, const Destination & destination, ECN ecn)
		{
			iovec iov{
				.iov_base = const_cast<void *>(data),
				.iov_len = size
			};
			
			msghdr message{
				.msg_name = const_cast<sockaddr *>(destination.addr),
				.msg_namelen = destination.addrlen,
				.msg_iov = &iov,
				.msg_iovlen = 1
			};
			
			if (ecn != _ecn) {
				set_ecn(_descriptor, destination.addr->sa_family, ecn);
			}
			
			ssize_t result;
			
			do {
				result = sendmsg(_descriptor, &message, 0);
			} while (result == -1 && errno == EINTR);
			
			if (result == -1) {
				throw std::runtime_error("sendmsg: " + std::string(strerror(errno)));
			}
			
			return result;
		}
		
		size_t Socket::receive_packet(void *data, std::size_t size, Address &address, ECN &ecn)
		{
			iovec iov = {
				.iov_base = data,
				.iov_len = size
			};
			
			uint8_t message_control[CMSG_SPACE(sizeof(uint8_t))];
			
			msghdr message = {
				.msg_name = &address.data.sa,
				.msg_namelen = sizeof(address.length),
				.msg_iov = &iov,
				.msg_iovlen = 1,
				.msg_control = message_control,
				.msg_controllen = sizeof(message_control)
			};
			
			ssize_t result;
			
			Scheduler::Monitor monitor(_descriptor);
			
			do {
				result = recvmsg(_descriptor, &message, 0);
				
				if (result == -1) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						monitor.wait_readable();
					} else if (errno == EINTR) {
						// ignore
					} else {
						throw std::system_error(errno, std::generic_category(), "recvmsg");
					}
				}
			} while (result == -1 && errno == EINTR);
			
			if (result == -1) {
				throw std::runtime_error("recvmsg: " + std::string(strerror(errno)));
			}
			
			_ecn = ecn = get_ecn(&message, address.data.sa.sa_family);
			
			return result;
		}
	}
}
