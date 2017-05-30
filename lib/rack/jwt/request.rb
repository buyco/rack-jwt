module Rack
  module JWT
    # Manage token in request object
    class Request < ::Rack::Request

      attr_reader :options

      # The last segment gets dropped for 'none' algorithm since there is no
      # signature so both of these patterns are valid. All character chunks
      # are base64url format and periods.
      #   Bearer abc123.abc123.abc123
      #   Bearer abc123.abc123.
      BEARER_TOKEN_REGEX = %r{
        ^Bearer\s{1}(       # starts with Bearer and a single space
        [a-zA-Z0-9\-\_]+\.  # 1 or more chars followed by a single period
        [a-zA-Z0-9\-\_]+\.  # 1 or more chars followed by a single period
        [a-zA-Z0-9\-\_]*    # 0 or more chars, no trailing chars
        )$
      }x

      def initialize(env, opts = {})
        @from_header  = false
        @from_cookie  = false
        @from_params  = false
        @options      = opts
        super(env)
      end

      def from_header?
        @from_header
      end

      def from_cookie?
        @from_cookie
      end

      def from_params?
        @from_params
      end

      def token
        return @token if defined? @token # return nil if not auth token

        @token = extract_token_from_header || extract_token_from_cookie || extract_token_from_query_string
      end

      def token?
        !token.nil? && !token.empty?
      end

      def extract_token_from_header
        token = BEARER_TOKEN_REGEX.match(env['HTTP_AUTHORIZATION'])[1].strip if env['HTTP_AUTHORIZATION'] && BEARER_TOKEN_REGEX =~ env['HTTP_AUTHORIZATION']
        @from_header = true
        token
      end

      def cookie_key
        @options[:cookie_key] || 'auth_token'
      end

      def extract_token_from_cookie
        token = cookies[cookie_key].strip if cookies[cookie_key]
        @from_cookie = true
        token
      end

      def extract_token_from_query_string
        token = params['auth_token'].strip if params['auth_token']
        @from_params = true
        token
      end
    end
  end
end
