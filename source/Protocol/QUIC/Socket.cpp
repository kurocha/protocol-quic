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
#include <stdexcept>

#include <unistd.h>
#include <net/if.h>

 #ifndef SOCK_NONBLOCK
 #include <fcntl.h>
 #define SOCK_NONBLOCK O_NONBLOCK
 #endif

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
		
		std::string LocalAddress::to_string() const
		{
			std::string interface_name(IF_NAMESIZE, '\0');
			if_indextoname(interface_index, interface_name.data());
			
			std::string name = Address::to_string();
			name += "%";
			name += interface_name;
			
			return name;
		}
		
		std::optional<LocalAddress> local_address(msghdr *msg, int family)
		{
			if (family == AF_INET) {
				for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
						auto pktinfo = reinterpret_cast<in_pktinfo *>(CMSG_DATA(cmsg));
						LocalAddress address;
						address.interface_index = pktinfo->ipi_ifindex;
						address.length = sizeof(address.data.in);
						address.data.in.sin_family = AF_INET;
						address.data.in.sin_addr = pktinfo->ipi_addr;
						return address;
					}
				}
			}
			else if (family == AF_INET6) {
				for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
						auto pktinfo = reinterpret_cast<in6_pktinfo *>(CMSG_DATA(cmsg));
						LocalAddress address;
						address.interface_index = pktinfo->ipi6_ifindex;
						address.length = sizeof(address.data.in6);
						address.data.in6.sin6_family = AF_INET6;
						address.data.in6.sin6_addr = pktinfo->ipi6_addr;
						return address;
					}
				}
			}
			
			return {};
		}
		
		Socket::Socket(int descriptor, const Address & address) : _descriptor(descriptor), _address(address)
		{
		}
		
		Socket::~Socket()
		{
			if (_descriptor >= 0) {
				::close(_descriptor);
			}
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
		
		void set_ecn(int descriptor, int family, ECN ecn) {
			unsigned int tos = static_cast<unsigned int>(ecn);
			
			switch (family) {
			case AF_INET:
				if (setsockopt(descriptor, IPPROTO_IP, IP_TOS, &tos, static_cast<socklen_t>(sizeof(ecn))) == -1) {
					throw std::runtime_error("set_ecn:setsockopt(IP_TOS): " + std::string(strerror(errno)));
				}
				break;
			case AF_INET6:
				if (setsockopt(descriptor, IPPROTO_IPV6, IPV6_TCLASS, &tos, static_cast<socklen_t>(sizeof(ecn))) == -1) {
					throw std::runtime_error("set_ecn:setsockopt(IPV6_TCLASS): " + std::string(strerror(errno)));
				}
				break;
			}
		}
		
		void set_recv_ecn(int descriptor, int family) {
			unsigned int tos = 1;
			switch (family) {
			case AF_INET:
				if (setsockopt(descriptor, IPPROTO_IP, IP_RECVTOS, &tos, static_cast<socklen_t>(sizeof(tos))) == -1) {
					throw std::runtime_error("set_recv_ecn:setsockopt(IP_RECVTOS)" + std::string(strerror(errno)));
				}
				break;
			case AF_INET6:
				if (setsockopt(descriptor, IPPROTO_IPV6, IPV6_RECVTCLASS, &tos, static_cast<socklen_t>(sizeof(tos))) == -1) {
					throw std::runtime_error("set_recv_ecn:setsockopt(IPV6_RECVTCLASS)" + std::string(strerror(errno)));
				}
				break;
			}
		}

		void set_ip_mtu_discover(int descriptor, int family) {
#if defined(IP_MTU_DISCOVER) && defined(IPV6_MTU_DISCOVER)
			int value;
			
			switch (family) {
			case AF_INET:
				value = IP_PMTUDISC_DO;
				if (setsockopt(descriptor, IPPROTO_IP, IP_MTU_DISCOVER, &value, static_cast<socklen_t>(sizeof(value))) == -1) {
					throw std::runtime_error("setsockopt: IP_MTU_DISCOVER" + std::string(strerror(errno)));
				}
				break;
			case AF_INET6:
				value = IPV6_PMTUDISC_DO;
				if (setsockopt(descriptor, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &value, static_cast<socklen_t>(sizeof(value))) == -1) {
					throw std::runtime_error("setsockopt: IPV6_MTU_DISCOVER" + std::string(strerror(errno)));
				}
				break;
			}
#endif
		}

		void set_ip_dontfrag(int descriptor, int family) {
#if defined(IP_DONTFRAG) && defined(IPV6_DONTFRAG)
			int value = 1;
			
			switch (family) {
			case AF_INET:
				if (setsockopt(descriptor, IPPROTO_IP, IP_DONTFRAG, &value, static_cast<socklen_t>(sizeof(value))) == -1) {
					throw std::runtime_error("set_ip_dontfrag:setsockopt(IP_DONTFRAG): " + std::string(strerror(errno)));
				}
				break;
			case AF_INET6:
				if (setsockopt(descriptor, IPPROTO_IPV6, IPV6_DONTFRAG, &value, static_cast<socklen_t>(sizeof(value))) == -1) {
					throw std::runtime_error("set_ip_dontfrag:setsockopt(IPV6_DONTFRAG): " + std::string(strerror(errno)));
				}
				break;
			}
#endif
		}
		
		int create_udp_socket(int domain) {
			auto descriptor = socket(domain, SOCK_DGRAM | SOCK_NONBLOCK, 0);
			
			if (descriptor == -1) {
				throw std::runtime_error("socket: " + std::string(strerror(errno)));
			}
			
			set_recv_ecn(descriptor, domain);
			set_ip_mtu_discover(descriptor, domain);
			set_ip_dontfrag(descriptor, domain);
			
			return descriptor;
		}
		
		Socket Socket::connect(const char *host, const char *service) {
			addrinfo hints{.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM};
			addrinfo *results;
			
			if (auto error = getaddrinfo(host, service, &hints, &results); error != 0) {
				throw std::runtime_error("getaddrinfo: " + std::string(gai_strerror(error)));
			}
			
			auto free_results = defer([&]{
				freeaddrinfo(results);
			});
			
			int descriptor = -1;
			
			addrinfo *iterator = results;
			
			while (iterator) {
				descriptor = create_udp_socket(iterator->ai_family);
				if (descriptor != -1) {
					break;
				}
				
				iterator = iterator->ai_next;
			}
			
			if (!iterator) {
				throw std::runtime_error("Could not create socket");
			}
			
			return Socket(descriptor, iterator);
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
			
			set_ecn(_descriptor, destination.addr->sa_family, ecn);
			
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
			
			do {
				result = recvmsg(_descriptor, &message, 0);
			} while (result == -1 && (errno == EINTR || errno == EAGAIN));
			
			if (result == -1) {
				throw std::runtime_error("recvmsg: " + std::string(strerror(errno)));
			}
			
			ecn = get_ecn(&message, address.data.sa.sa_family);
			
			return result;
		}
	}
}
