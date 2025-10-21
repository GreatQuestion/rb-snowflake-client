# frozen_string_literal: true

require 'spec_helper'

RSpec.describe RubySnowflake::Client::OAuth2AuthManager do
  let(:access_token) { 'test_access_token' }
  let(:expires_at) { Time.now + 3600 }

  subject do
    described_class.new(access_token, expires_at: expires_at)
  end

  describe '#initialize' do
    it 'sets the correct attributes' do
      expect(subject.instance_variable_get(:@access_token)).to eq(access_token)
      expect(subject.instance_variable_get(:@expires_at)).to eq(expires_at)
    end

    context 'without expires_at' do
      subject { described_class.new(access_token) }

      it 'sets access_token and leaves expires_at nil' do
        expect(subject.instance_variable_get(:@access_token)).to eq(access_token)
        expect(subject.instance_variable_get(:@expires_at)).to be_nil
      end
    end
  end

  describe '#token' do
    it 'returns the access token' do
      expect(subject.token).to eq(access_token)
    end
  end

  describe '#token_info' do
    it 'returns token metadata' do
      info = subject.token_info

      expect(info[:token_type]).to eq('Bearer')
      expect(info[:expires_at]).to eq(expires_at.to_i)
    end

    context 'when expires_at is nil' do
      subject { described_class.new(access_token) }

      it 'returns nil for expires_at' do
        info = subject.token_info
        expect(info[:token_type]).to eq('Bearer')
        expect(info[:expires_at]).to be_nil
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

  describe '#token_type' do
    it 'returns OAUTH' do
      expect(subject.token_type).to eq('OAUTH')
    end
  end

  describe 'AuthenticationError' do
    it 'is a StandardError' do
      expect(RubySnowflake::Client::OAuth2AuthManager::AuthenticationError).to be < StandardError
    end
  end
end
