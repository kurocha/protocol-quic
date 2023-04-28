//
//  Random.hpp
//  This file is part of the "Protocol::QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 16/4/2023.
//  Copyright, 2023, by Samuel Williams. All rights reserved.
//

#pragma once

#include <random>
#include <array>

namespace Protocol
{
	namespace QUIC
	{
		// The Random class provides functionality for generating secure random numbers and secrets for use in the QUIC implementation. This class uses the Mersenne Twister 19937 algorithm to generate pseudo-random numbers, and the system's hardware random number generator to generate secure random numbers.
		class Random
		{
		public:
			// Generate a buffer of random data with secure entropy.
			// This method should be used when generating cryptographic material.
			static void generate_secure(std::uint8_t *buffer, std::size_t size);
			
			// Generate a secret with secure entropy.
			// This method should be used when generating secret keys or other secret material.
			static void generate_secret(std::array<std::uint8_t, 32> &buffer);
			
			Random();
			~Random();
			
			// Generate a buffer of random data with non-secure entropy.
			// This method should be used when generating non-cryptographic material.
			void generate(std::uint8_t *buffer, std::size_t size);
			
		private:
			std::mt19937 _generator;
		};
	}
}
