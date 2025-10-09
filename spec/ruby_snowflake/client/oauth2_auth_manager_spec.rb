require 'spec_helper'

RSpec.describe RubySnowflake::Client::OAuth2AuthManager do
  let(:access_token) { 'test_access_token' }
  let(:refresh_token) { 'test_refresh_token' }
  let(:expires_at) { Time.now + 3600 }
  let(:uri) { 'https://test.snowflakecomputing.com' }
  let(:client_id) { 'test_client_id' }
  let(:client_secret) { 'test_client_secret' }
  let(:token_refresh_threshold) { 60 }

  subject do
    described_class.new(
      access_token,
      refresh_token: refresh_token,
      expires_at: expires_at,
      uri: uri,
      client_id: client_id,
      client_secret: client_secret,
      token_refresh_threshold: token_refresh_threshold
    )
  end

  describe '#initialize' do
    it 'sets the correct attributes' do
      expect(subject.instance_variable_get(:@access_token)).to eq(access_token)
      expect(subject.instance_variable_get(:@refresh_token)).to eq(refresh_token)
      expect(subject.instance_variable_get(:@expires_at)).to eq(expires_at)
      expect(subject.instance_variable_get(:@uri)).to eq(uri)
      expect(subject.instance_variable_get(:@client_id)).to eq(client_id)
      expect(subject.instance_variable_get(:@client_secret)).to eq(client_secret)
      expect(subject.instance_variable_get(:@token_refresh_threshold)).to eq(token_refresh_threshold)
    end

    it 'creates a semaphore for thread safety' do
      semaphore = subject.instance_variable_get(:@token_semaphore)
      expect(semaphore).to be_a(Concurrent::Semaphore)
    end
  end

  describe '#token_type' do
    it 'returns OAUTH' do
      expect(subject.token_type).to eq('OAUTH')
    end
  end

  describe '#token_expired?' do
    context 'when no access token exists' do
      before do
        subject.instance_variable_set(:@access_token, nil)
      end

      it 'returns true' do
        expect(subject.token_expired?).to be true
      end
    end

    context 'when no expiration time is provided' do
      before do
        subject.instance_variable_set(:@expires_at, nil)
      end

      it 'returns false' do
        expect(subject.token_expired?).to be false
      end
    end

    context 'when token is expired' do
      before do
        subject.instance_variable_set(:@expires_at, Time.now - 100)
      end

      it 'returns true' do
        expect(subject.token_expired?).to be true
      end
    end

    context 'when token will expire within threshold' do
      before do
        subject.instance_variable_set(:@expires_at, Time.now + 30)
      end

      it 'returns true' do
        expect(subject.token_expired?).to be true
      end
    end

    context 'when token is valid and not expiring soon' do
      before do
        subject.instance_variable_set(:@expires_at, Time.now + 3600)
      end

      it 'returns false' do
        expect(subject.token_expired?).to be false
      end
    end
  end

  describe '#token' do
    context 'when token is not expired' do
      before do
        allow(subject).to receive(:token_expired?).and_return(false)
      end

      it 'returns the access token' do
        expect(subject.token).to eq(access_token)
      end
    end

    context 'when token is expired and refresh is not available' do
      before do
        allow(subject).to receive(:token_expired?).and_return(true)
        subject.instance_variable_set(:@refresh_token, nil)
      end

      it 'raises AuthenticationError' do
        expect { subject.token }.to raise_error(
          RubySnowflake::Client::OAuth2AuthManager::AuthenticationError,
          'Token expired and no refresh capability available'
        )
      end
    end

    context 'when token is expired and refresh is available' do
      let(:new_access_token) { 'new_access_token' }
      let(:new_expires_at) { Time.now + 3600 }

      before do
        allow(subject).to receive(:token_expired?).and_return(true)
        allow(subject).to receive(:refresh_access_token).and_return(new_access_token)
        subject.instance_variable_set(:@access_token, new_access_token)
        subject.instance_variable_set(:@expires_at, new_expires_at)
      end

      it 'refreshes the token and returns new access token' do
        expect(subject.token).to eq(new_access_token)
      end
    end
  end

  describe '#refresh_token!' do
    let(:new_access_token) { 'new_access_token' }
    let(:new_expires_at) { Time.now + 3600 }

    before do
      allow(subject).to receive(:refresh_access_token).and_return(new_access_token)
      subject.instance_variable_set(:@access_token, new_access_token)
      subject.instance_variable_set(:@expires_at, new_expires_at)
    end

    it 'calls refresh_access_token' do
      expect(subject).to receive(:refresh_access_token)
      subject.refresh_token!
    end

    it 'returns the new access token' do
      expect(subject.refresh_token!).to eq(new_access_token)
    end
  end

  describe '#token_info' do
    it 'returns token metadata' do
      info = subject.token_info

      expect(info[:token_type]).to eq('Bearer')
      expect(info[:expires_at]).to eq(expires_at.to_i)
      expect(info[:has_refresh_token]).to be true
      expect(info[:refresh_capable]).to be true
    end

    context 'when refresh token is nil' do
      before do
        subject.instance_variable_set(:@refresh_token, nil)
      end

      it 'indicates no refresh capability' do
        info = subject.token_info
        expect(info[:has_refresh_token]).to be false
        expect(info[:refresh_capable]).to be false
      end
    end
  end

  describe '#update_token' do
    let(:new_access_token) { 'new_access_token' }
    let(:new_expires_at) { Time.now + 7200 }

    it 'updates the access token' do
      subject.update_token(new_access_token, expires_at: new_expires_at)

      expect(subject.instance_variable_get(:@access_token)).to eq(new_access_token)
      expect(subject.instance_variable_get(:@expires_at)).to eq(new_expires_at)
    end

    it 'updates only access token when expires_at is not provided' do
      # Store the original expires_at value
      original_expires_at = subject.instance_variable_get(:@expires_at)

      subject.update_token(new_access_token)

      expect(subject.instance_variable_get(:@access_token)).to eq(new_access_token)
      # When expires_at is not provided, it should remain unchanged
      expect(subject.instance_variable_get(:@expires_at)).to eq(original_expires_at)
    end
  end

  describe '#token_url' do
    it 'returns the correct token URL' do
      expect(subject.send(:token_url)).to eq("#{uri}/oauth/token-request")
    end
  end

  describe '#refresh_access_token' do
    let(:mock_response) { double('response', code: '200', body: response_body) }
    let(:response_body) do
      {
        access_token: 'new_access_token',
        expires_in: 3600,
        refresh_token: 'new_refresh_token'
      }.to_json
    end

    before do
      http_double = double('http')
      allow(Net::HTTP).to receive(:new).and_return(http_double)
      allow(http_double).to receive(:use_ssl=)
      allow(http_double).to receive(:request).and_return(mock_response)
    end

    it 'makes a POST request to the token URL' do
      http_double = double('http')
      expect(Net::HTTP).to receive(:new).and_return(http_double)
      expect(http_double).to receive(:use_ssl=).with(true)
      expect(http_double).to receive(:request).and_return(mock_response)

      subject.send(:refresh_access_token)
    end

    it 'updates tokens with response data' do
      subject.send(:refresh_access_token)

      expect(subject.instance_variable_get(:@access_token)).to eq('new_access_token')
      expect(subject.instance_variable_get(:@refresh_token)).to eq('new_refresh_token')
      expect(subject.instance_variable_get(:@expires_at)).to be_within(5).of(Time.now + 3600)
    end

    context 'when response is not successful' do
      let(:mock_response) { double('response', code: '400', body: 'Invalid request') }

      before do
        http_double = double('http')
        allow(Net::HTTP).to receive(:new).and_return(http_double)
        allow(http_double).to receive(:use_ssl=)
        allow(http_double).to receive(:request).and_return(mock_response)
      end

      it 'raises AuthenticationError' do
        expect { subject.send(:refresh_access_token) }.to raise_error(
          RubySnowflake::Client::OAuth2AuthManager::AuthenticationError,
          'Token refresh failed: Token refresh failed: 400 - Invalid request'
        )
      end
    end

    context 'when request fails' do
      before do
        allow(Net::HTTP).to receive(:new).and_raise(StandardError.new('Network error'))
      end

      it 'raises AuthenticationError with original error message' do
        expect { subject.send(:refresh_access_token) }.to raise_error(
          RubySnowflake::Client::OAuth2AuthManager::AuthenticationError,
          'Token refresh failed: Network error'
        )
      end
    end
  end

  describe 'thread safety' do
    it 'uses semaphore for thread safety' do
      semaphore = subject.instance_variable_get(:@token_semaphore)
      expect(semaphore).to be_a(Concurrent::Semaphore)
    end

    it 'acquires semaphore before refreshing token' do
      semaphore = subject.instance_variable_get(:@token_semaphore)
      expect(semaphore).to receive(:acquire).and_yield

      allow(subject).to receive(:refresh_access_token).and_return('new_token')
      subject.refresh_token!
    end
  end

  describe 'AuthenticationError' do
    it 'is a StandardError' do
      expect(RubySnowflake::Client::OAuth2AuthManager::AuthenticationError).to be < StandardError
    end
  end
end
