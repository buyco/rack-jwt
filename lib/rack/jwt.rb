require 'rack/jwt/version'

module Rack
  # JSON Web Token
  module JWT
    autoload :Auth, 'rack/jwt/auth'
    autoload :Token, 'rack/jwt/token'
    autoload :Request, 'rack/jwt/request'
  end
end
