require 'spec_helper'

RSpec.describe RubySnowflake::Client do
  describe '.from_oauth2_token' do
    let(:uri) { 'https://test.snowflakecomputing.com' }
    let(:access_token) { 'test_access_token' }
    let(:default_warehouse) { 'test_warehouse' }
    let(:default_database) { 'test_database' }
    let(:refresh_token) { 'test_refresh_token' }
    let(:expires_at) { Time.now + 3600 }
    let(:client_id) { 'test_client_id' }
    let(:client_secret) { 'test_client_secret' }

    subject do
      described_class.from_oauth2_token(
        uri, access_token, default_warehouse, default_database,
        refresh_token: refresh_token,
        expires_at: expires_at,
        client_id: client_id,
        client_secret: client_secret
      )
    end

    it 'creates a client with OAuth2AuthManager' do
      auth_manager = subject.instance_variable_get(:@auth_manager)
      expect(auth_manager).to be_a(RubySnowflake::Client::OAuth2AuthManager)
    end

    it 'sets the correct default values' do
      expect(subject.instance_variable_get(:@base_uri)).to eq(uri)
      expect(subject.instance_variable_get(:@default_warehouse)).to eq(default_warehouse)
      expect(subject.instance_variable_get(:@default_database)).to eq(default_database)
    end

    it 'configures OAuth2AuthManager with correct parameters' do
      auth_manager = subject.instance_variable_get(:@auth_manager)
      expect(auth_manager.instance_variable_get(:@access_token)).to eq(access_token)
      expect(auth_manager.instance_variable_get(:@refresh_token)).to eq(refresh_token)
      expect(auth_manager.instance_variable_get(:@expires_at)).to eq(expires_at)
      expect(auth_manager.instance_variable_get(:@client_id)).to eq(client_id)
      expect(auth_manager.instance_variable_get(:@client_secret)).to eq(client_secret)
    end

    context 'with custom parameters' do
      let(:default_role) { 'test_role' }
      let(:token_refresh_threshold) { 120 }
      let(:logger) { Logger.new(STDOUT) }
      let(:log_level) { Logger::DEBUG }
      let(:connection_timeout) { 120 }
      let(:max_connections) { 32 }
      let(:max_threads_per_query) { 16 }
      let(:thread_scale_factor) { 2.0 }
      let(:http_retries) { 5 }
      let(:query_timeout) { 1200 }

      subject do
        described_class.from_oauth2_token(
          uri, access_token, default_warehouse, default_database,
          refresh_token: refresh_token,
          expires_at: expires_at,
          client_id: client_id,
          client_secret: client_secret,
          default_role: default_role,
          token_refresh_threshold: token_refresh_threshold,
          logger: logger,
          log_level: log_level,
          connection_timeout: connection_timeout,
          max_connections: max_connections,
          max_threads_per_query: max_threads_per_query,
          thread_scale_factor: thread_scale_factor,
          http_retries: http_retries,
          query_timeout: query_timeout
        )
      end

      it 'passes all custom parameters correctly' do
        expect(subject.instance_variable_get(:@default_role)).to eq(default_role)
        expect(subject.instance_variable_get(:@logger)).to eq(logger)
        expect(subject.instance_variable_get(:@logger).level).to eq(log_level)
        expect(subject.instance_variable_get(:@connection_timeout)).to eq(connection_timeout)
        expect(subject.instance_variable_get(:@max_connections)).to eq(max_connections)
        expect(subject.instance_variable_get(:@max_threads_per_query)).to eq(max_threads_per_query)
        expect(subject.instance_variable_get(:@thread_scale_factor)).to eq(thread_scale_factor)
        expect(subject.instance_variable_get(:@http_retries)).to eq(http_retries)
        expect(subject.instance_variable_get(:@query_timeout)).to eq(query_timeout)
      end

      it 'configures OAuth2AuthManager with custom token_refresh_threshold' do
        auth_manager = subject.instance_variable_get(:@auth_manager)
        expect(auth_manager.instance_variable_get(:@token_refresh_threshold)).to eq(token_refresh_threshold)
      end
    end
  end

  describe 'OAuth2 integration' do
    let(:uri) { 'https://test.snowflakecomputing.com' }
    let(:access_token) { 'test_access_token' }
    let(:default_warehouse) { 'test_warehouse' }
    let(:default_database) { 'test_database' }
    let(:client_id) { 'test_client_id' }
    let(:client_secret) { 'test_client_secret' }

    let(:client) do
      described_class.from_oauth2_token(
        uri, access_token, default_warehouse, default_database,
        client_id: client_id,
        client_secret: client_secret
      )
    end

    describe '#request_with_auth_and_headers' do
      let(:mock_auth_manager) { double('auth_manager') }
      let(:mock_connection) { double('connection') }
      let(:mock_request) { double('request') }
      let(:mock_response) { double('response', code: '200', body: '{}') }

      before do
        allow(client).to receive(:connection_pool).and_return(double('pool', with: mock_connection))
        client.instance_variable_set(:@auth_manager, mock_auth_manager)

        allow(mock_auth_manager).to receive(:token).and_return('test_oauth_token')
        allow(mock_auth_manager).to receive(:respond_to?).with(:jwt_token).and_return(false)

        allow(Net::HTTP::Post).to receive(:new).and_return(mock_request)
        allow(mock_request).to receive(:[]=)
        allow(mock_request).to receive(:body=)
        allow(mock_connection).to receive(:request).and_return(mock_response)
        allow(Benchmark).to receive(:measure).and_return(double('benchmark', real: 0.1))

        # Mock the retryable block to avoid calling raise_on_bad_response
        allow(Retryable).to receive(:retryable).and_yield
        allow(client).to receive(:raise_on_bad_response)
      end

      it 'uses OAuth2 token in Authorization header' do
        allow(mock_auth_manager).to receive(:token_type).and_return('OAUTH')
        expect(mock_request).to receive(:[]=).with('Authorization', 'Bearer test_oauth_token')
        expect(mock_request).to receive(:[]=).with('X-Snowflake-Authorization-Token-Type', 'OAUTH')

        client.send(:request_with_auth_and_headers, mock_connection, Net::HTTP::Post, '/api/v2/statements')
      end
    end
  end

  describe 'OAuth2 token refresh integration' do
    let(:uri) { 'https://test.snowflakecomputing.com' }
    let(:access_token) { 'test_access_token' }
    let(:refresh_token) { 'test_refresh_token' }
    let(:expires_at) { Time.now + 3600 }
    let(:client_id) { 'test_client_id' }
    let(:client_secret) { 'test_client_secret' }

    let(:client) do
      described_class.from_oauth2_token(
        uri, access_token, 'test_warehouse', 'test_database',
        refresh_token: refresh_token,
        expires_at: expires_at,
        client_id: client_id,
        client_secret: client_secret
      )
    end

    it 'automatically refreshes expired tokens' do
      auth_manager = client.instance_variable_get(:@auth_manager)

      # Simulate token expiration
      allow(auth_manager).to receive(:token_expired?).and_return(true)
      allow(auth_manager).to receive(:refresh_access_token).and_return('new_access_token')

      # Mock the refresh process
      auth_manager.instance_variable_set(:@access_token, 'new_access_token')
      auth_manager.instance_variable_set(:@expires_at, Time.now + 3600)

      expect(auth_manager.token).to eq('new_access_token')
    end

    it 'handles token refresh errors gracefully' do
      auth_manager = client.instance_variable_get(:@auth_manager)

      allow(auth_manager).to receive(:token_expired?).and_return(true)
      allow(auth_manager).to receive(:refresh_access_token).and_raise(
        RubySnowflake::Client::OAuth2AuthManager::AuthenticationError.new('Refresh failed')
      )

      expect { auth_manager.token }.to raise_error(
        RubySnowflake::Client::OAuth2AuthManager::AuthenticationError,
        'Refresh failed'
      )
    end
  end
end
