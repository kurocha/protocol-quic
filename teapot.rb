# Teapot v3.5.0 configuration generated at 2023-04-17 12:31:24 +1200

required_version "3.0"

define_project "protocol-quic" do |project|
	project.title = "Protocol QUIC"
end

# Build Targets

define_target 'protocol-quic-library' do |target|
	target.depends 'Language/C++17'
	target.depends 'Build/Compile/Commands'
	
	target.depends 'Library/ngtcp2', public: true
	
	target.provides 'Library/Protocol/QUIC' do
		source_root = target.package.path + 'source'
		
		library_path = build static_library: 'ProtocolQUIC', source_files: source_root.glob('Protocol/QUIC/**/*.cpp')
		
		append linkflags library_path
		append header_search_paths source_root
		
		compile_commands destination_path: (source_root + "compile_commands.json")
	end
end

define_target 'protocol-quic-test' do |target|
	target.depends 'Library/Protocol/QUIC'
	target.depends 'Library/UnitTest'
	
	target.depends 'Language/C++17'
	target.depends 'Build/Compile/Commands'
	
	target.provides 'Test/Protocol/QUIC' do |arguments|
		test_root = target.package.path + 'test'
		
		run tests: 'ProtocolQUIC-tests', source_files: test_root.glob('Protocol/QUIC/**/*.cpp'), arguments: arguments
		
		compile_commands destination_path: (test_root + "compile_commands.json")
	end
end

# Configurations

define_configuration 'development' do |configuration|
	configuration[:source] = "https://github.com/kurocha"
	configuration.import "protocol-quic"
	
	# Provides all the build related infrastructure:
	configuration.require 'platforms'
	
	# Provides unit testing infrastructure and generators:
	configuration.require 'unit-test'
	
	# Provides some useful C++ generators:
	configuration.require 'generate-template'
	configuration.require 'generate-cpp-class'
	
	configuration.require "build-compile-commands"
end

define_configuration "protocol-quic" do |configuration|
	configuration.public!
	
	configuration.require "nghttp3"
end
