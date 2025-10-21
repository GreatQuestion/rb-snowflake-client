# frozen_string_literal: true

module RubySnowflake
  class Client
    class OAuth2AuthManager
      class AuthenticationError < StandardError; end

      # Initialize OAuth2 authentication manager with existing tokens
      # @param access_token [String] OAuth2 access token
      # @param expires_at [Time, nil] Token expiration time (optional)
      def initialize(access_token, expires_at: nil)
        @access_token = access_token
        @expires_at = expires_at
      end

      # Returns the OAuth2 access token
      # @return [String] the access token
      def token
        @access_token
      end


      def token_info
        {
          token_type: 'Bearer',
          expires_at: @expires_at&.to_i
        }
      end

      def update_token(access_token, expires_at: nil)
        @access_token = access_token
        @expires_at = expires_at unless expires_at.nil?
      end

      def token_type
        'OAUTH'
      end
    end
  end
end
