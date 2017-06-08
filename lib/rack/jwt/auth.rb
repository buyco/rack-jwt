require 'jwt'

module Rack
  module JWT
    # Authentication middleware
    class Auth
      attr_reader :secret
      attr_reader :verify
      attr_reader :options
      attr_reader :exclude
      attr_reader :token_param
      attr_reader :authorized_roles

      SUPPORTED_ALGORITHMS = %w(none HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512).freeze
      DEFAULT_ALGORITHM = 'HS256'.freeze
      TOKEN_PARAM = 'auth_token'.freeze

      # Initialization should fail fast with an ArgumentError
      # if any args are invalid.
      def initialize(app, opts = {})
        @app              = app
        @secret           = opts.fetch(:secret, nil)
        @verify           = opts.fetch(:verify, true)
        @options          = opts.fetch(:options, {})
        @exclude          = opts.fetch(:exclude, [])
        @authorized_roles = opts.fetch(:authorized_roles, [])
        @token_param      = @options.fetch(:token_param, TOKEN_PARAM)

        @secret  = @secret.strip if @secret.is_a?(String)
        @options[:algorithm] = DEFAULT_ALGORITHM if @options[:algorithm].nil?

        check_secret_type!
        check_secret!
        check_secret_and_verify_for_none_alg!
        check_verify_type!
        check_options_type!
        check_valid_algorithm!
        check_exclude_type!
        check_authorized_roles!
      end

      def call(env)
        return @app.call(env) if path_matches_excluded_path?(env)

        request = Rack::JWT::Request.new(env, @options)

        if missing_auth_token?(request)
          if request.xhr? || @options[:auth_url].nil?
            return_error('Missing Authorization token')
          else
            return_to = @options[:auth_url_return_to] || request.url
            [302, {'Location' => "#{@options[:auth_url]}?return_to=#{return_to}", 'Content-Type' => 'text/html'}, ['Moved Temporary']]
          end
        else
          verify_token(env, request)
        end
      end

      private

      def redirect_without_token(request)
        params = Rack::Utils.parse_nested_query(request.query_string).dup
        params.delete('auth_token')
        query_without_token = Rack::Utils.build_nested_query(params)

        location = query_without_token.empty? ? request.path : "#{request.path}?#{query_without_token}"

        cookie_value = { value: request.token, path: '/' }
        cookie_value[:domain] = @options[:cookie_domain] if @options[:cookie_domain]
        cookie_value[:expires] = Time.now + @options[:cookie_expire_after] if @options[:cookie_expire_after]
        cookie_key = @options[:cookie_key] || token_param
        cookie = Rack::Utils.add_cookie_to_header(nil, cookie_key, cookie_value) if request.from_params?

        [302, {'Location' => location, 'Content-Type' => 'text/html', 'Set-Cookie' => cookie}, ['Moved Permanently']]
      end

      def verify_token(env, request)
        # extract the token from the Authorization: Bearer header
        # with a regex capture group.
        token = request.token

        begin
          decoded_token = Token.decode(token, @secret, @verify, @options)
          payload = decoded_token.first
          env['jwt.payload'] = payload
          env['jwt.header'] = decoded_token.last

          raise Rack::JWT::RoleError unless @authorized_roles.empty? || @authorized_roles.include?(payload['role'])

          #
          # TODO add xss protection here ?
          # TODO set expiration based on jwt expiration
          #
          return redirect_without_token(request) if request.from_params?
          # Rack::Utils.set_cookie_header!(headers, token_param, {value: token, path: '/'}) if request.from_params?

          @app.call(env)

        rescue Rack::JWT::RoleError
          return_error('Unauthorized JWT token : unauthorized role')
        rescue ::JWT::VerificationError
          return_error('Invalid JWT token : Signature Verification Error')
        rescue ::JWT::ExpiredSignature
          return_error('Invalid JWT token : Expired Signature (exp)')
        rescue ::JWT::IncorrectAlgorithm
          return_error('Invalid JWT token : Incorrect Key Algorithm')
        rescue ::JWT::ImmatureSignature
          return_error('Invalid JWT token : Immature Signature (nbf)')
        rescue ::JWT::InvalidIssuerError
          return_error('Invalid JWT token : Invalid Issuer (iss)')
        rescue ::JWT::InvalidIatError
          return_error('Invalid JWT token : Invalid Issued At (iat)')
        rescue ::JWT::InvalidAudError
          return_error('Invalid JWT token : Invalid Audience (aud)')
        rescue ::JWT::InvalidSubError
          return_error('Invalid JWT token : Invalid Subject (sub)')
        rescue ::JWT::InvalidJtiError
          return_error('Invalid JWT token : Invalid JWT ID (jti)')
        rescue ::JWT::DecodeError
          return_error('Invalid JWT token : Decode Error')
        end
      end

      def check_secret_type!
        unless @secret.nil? ||
               @secret.is_a?(String) ||
               @secret.is_a?(OpenSSL::PKey::RSA) ||
               @secret.is_a?(OpenSSL::PKey::EC)
          raise ArgumentError, 'secret argument must be a valid type'
        end
      end

      def check_secret!
        if @secret.nil? || (@secret.is_a?(String) && @secret.empty?)
          unless @options[:algorithm] == 'none'
            raise ArgumentError, 'secret argument can only be nil/empty for the "none" algorithm'
          end
        end
      end

      def check_secret_and_verify_for_none_alg!
        if @options && @options[:algorithm] && @options[:algorithm] == 'none'
          unless @secret.nil? && @verify.is_a?(FalseClass)
            raise ArgumentError, 'when "none" the secret must be "nil" and verify "false"'
          end
        end
      end

      def check_verify_type!
        unless verify.is_a?(TrueClass) || verify.is_a?(FalseClass)
          raise ArgumentError, 'verify argument must be true or false'
        end
      end

      def check_options_type!
        raise ArgumentError, 'options argument must be a Hash' unless options.is_a?(Hash)
      end

      def check_valid_algorithm!
        unless @options &&
               @options[:algorithm] &&
               SUPPORTED_ALGORITHMS.include?(@options[:algorithm])
          raise ArgumentError, 'algorithm argument must be a supported type'
        end
      end

      def check_exclude_type!
        unless @exclude.is_a?(Array)
          raise ArgumentError, 'exclude argument must be an Array'
        end

        @exclude.each do |x|
          unless x.is_a?(String)
            raise ArgumentError, 'each exclude Array element must be a String'
          end

          if x.empty?
            raise ArgumentError, 'each exclude Array element must not be empty'
          end

          unless x.start_with?('/')
            raise ArgumentError, 'each exclude Array element must start with a /'
          end
        end
      end

      def check_authorized_roles!
        unless @authorized_roles.is_a?(Array)
          raise ArgumentError, 'authorized_roles argument must be an Array'
        end

        @authorized_roles.each do |x|
          unless x.is_a?(String)
            raise ArgumentError, 'each exclude Array element must be a String'
          end

          if x.empty?
            raise ArgumentError, 'each exclude Array element must not be empty'
          end
        end
      end

      def path_matches_excluded_path?(env)
        @exclude.any? { |ex| env['PATH_INFO'].start_with?(ex) }
      end

      def missing_auth_token?(request)
        !request.token?
      end

      def return_error(message)
        body    = { success: false, error: message }.to_json
        headers = { 'Content-Type' => 'application/json', 'Content-Length' => body.bytesize.to_s }

        [401, headers, [body]]
      end
    end
  end
end
