# frozen_string_literal: true

require 'concurrent'

module RubySnowflake
  class Client
    class OAuth2AuthManager
      # Initialize OAuth2 authentication manager with existing tokens
      # @param access_token [String] OAuth2 access token
      # @param refresh_token [String, nil] OAuth2 refresh token (optional)
      # @param expires_at [Time, nil] Token expiration time (optional)
      # @param token_url [String] OAuth2 token endpoint URL for refresh
      # @param client_id [String] OAuth2 client ID for refresh
      # @param client_secret [String] OAuth2 client secret for refresh
      # @param token_refresh_threshold [Integer] seconds before expiry to refresh token (default: 60)
      def initialize(
        access_token,
        refresh_token: nil,
        expires_at: nil,
        token_url: nil,
        client_id: nil,
        client_secret: nil,
        token_refresh_threshold: 60
      )
        @access_token = access_token
        @refresh_token = refresh_token
        @expires_at = expires_at
        @token_url = token_url
        @client_id = client_id
        @client_secret = client_secret
        @token_refresh_threshold = token_refresh_threshold

        @token_semaphore = Concurrent::Semaphore.new(1)
      end

      # Returns the OAuth2 access token
      # @return [String] the access token
      def token
        return @access_token unless token_expired?

        @token_semaphore.acquire do
          # Double-check after acquiring semaphore
          return @access_token unless token_expired?

          unless @refresh_token && @token_url && @client_id && @client_secret
            raise AuthenticationError, 'Token expired and no refresh capability available'
          end

          refresh_access_token
        end

        @access_token
      end

      # Returns the token type for Snowflake headers
      # @return [String] ""
      def token_type
        'OAUTH'
      end

      # Returns whether the current token is expired or will expire soon
      # @return [Boolean] true if token needs refresh
      def token_expired?
        return true unless @access_token

        # If no expiration time is provided, assume token is valid
        return false unless @expires_at

        # Check if token is expired or will expire within threshold
        Time.now >= (@expires_at - @token_refresh_threshold)
      end

      # Manually refresh the token using refresh_token
      # @return [String] the new access token
      def refresh_token!
        @token_semaphore.acquire do
          refresh_access_token
        end
      end

      # Returns token information for debugging
      # @return [Hash] token metadata
      def token_info
        {
          token_type: 'Bearer',
          expires_at: @expires_at&.to_i,
          has_refresh_token: !@refresh_token.nil?,
          refresh_capable: !(@refresh_token.nil? || @token_url.nil? || @client_id.nil? || @client_secret.nil?)
        }
      end

      # Update token information (useful when token is refreshed externally)
      # @param access_token [String] new access token
      # @param expires_at [Time, nil] new expiration time
      def update_token(access_token, expires_at: nil)
        @access_token = access_token
        @expires_at = expires_at
      end

      private

      def refresh_access_token
        require 'net/http'
        require 'json'
        require 'uri'

        uri = URI(@token_url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true if uri.scheme == 'https'

        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/x-www-form-urlencoded'
        request.body = URI.encode_www_form({
                                             grant_type: 'refresh_token',
                                             refresh_token: @refresh_token,
                                             client_id: @client_id,
                                             client_secret: @client_secret
                                           })

        response = http.request(request)

        unless response.code == '200'
          raise AuthenticationError, "Token refresh failed: #{response.code} - #{response.body}"
        end

        token_data = JSON.parse(response.body)
        @access_token = token_data['access_token']
        @expires_at = Time.now + token_data['expires_in'].to_i if token_data['expires_in']
        @refresh_token = token_data['refresh_token'] if token_data['refresh_token']

        @access_token
      rescue StandardError => e
        raise AuthenticationError, "Token refresh failed: #{e.message}"
      end

      # Custom error class for OAuth2 authentication failures
      class AuthenticationError < StandardError; end
    end
  end
end
