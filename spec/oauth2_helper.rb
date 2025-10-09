# frozen_string_literal: true

# Helper methods for OAuth2 testing
module OAuth2TestHelper
  def mock_oauth2_response(access_token: 'test_token', expires_in: 3600, refresh_token: nil)
    {
      access_token: access_token,
      expires_in: expires_in,
      refresh_token: refresh_token
    }.compact.to_json
  end

  def mock_http_response(code: '200', body: '{}')
    double('response', code: code, body: body)
  end

  def mock_http_client
    http_double = double('http')
    allow(Net::HTTP).to receive(:new).and_return(http_double)
    allow(http_double).to receive(:use_ssl=)
    http_double
  end

  def create_oauth2_client(access_token: 'test_token', **options)
    RubySnowflake::Client.from_oauth2_token(
      'https://test.snowflakecomputing.com',
      access_token,
      'test_warehouse',
      'test_database',
      **options
    )
  end

  def create_oauth2_auth_manager(access_token: 'test_token', **options)
    RubySnowflake::Client::OAuth2AuthManager.new(
      access_token,
      **options
    )
  end
end

RSpec.configure do |config|
  config.include OAuth2TestHelper
end
