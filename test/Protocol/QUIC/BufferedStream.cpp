//
//  BufferedStream.cpp
//  This file is part of the "Protocol QUIC" project and released under the MIT License.
//
//  Created by Samuel Williams on 26/5/2026.
//  Copyright, 2026, by Samuel Williams. All rights reserved.
//

#include <UnitTest/UnitTest.hpp>

#include <Protocol/QUIC/BufferedStream.hpp>
#include <Protocol/QUIC/Configuration.hpp>
#include <Protocol/QUIC/Connection.hpp>

namespace Protocol
{
	namespace QUIC
	{
		using namespace UnitTest::Expectations;

		class MockConnection : public Connection
		{
		public:
			using Connection::Connection;

		protected:
			Stream * create_stream(StreamID stream_id) override
			{
				(void)stream_id;
				return nullptr;
			}
		};

		class CountingStream : public BufferedStream
		{
		public:
			using BufferedStream::BufferedStream;

			std::size_t input_available_count = 0;

			void input_available() override
			{
				input_available_count += 1;
			}

			Status send_data() override
			{
				return Status::OK;
			}
		};

		UnitTest::Suite BufferedStreamTestSuite {
			"Protocol::QUIC::BufferedStream",

			{"it invokes input available when input data arrives",
				[](UnitTest::Examiner & examiner) {
					Configuration configuration;
					MockConnection connection(configuration);
					CountingStream stream(connection, 0);

					stream.receive_data(0, "Hello", 5, 0);

					examiner.expect(stream.input_buffer().data()).to(be == "Hello");
					examiner.expect(stream.input_available_count).to(be == 1);

					stream.receive_data(5, "", 0, NGTCP2_STREAM_DATA_FLAG_FIN);

					examiner.expect(stream.input_buffer().closed()).to(be == true);
					examiner.expect(stream.input_available_count).to(be == 2);
				}
			},
		};
	}
}
