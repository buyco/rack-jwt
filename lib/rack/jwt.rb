require 'rack/jwt/version'
require 'rack/jwt/error'

module Rack
  # JSON Web Token
  module JWT
    autoload :Auth, 'rack/jwt/auth'
    autoload :Token, 'rack/jwt/token'
    autoload :Request, 'rack/jwt/request'
  end
end
