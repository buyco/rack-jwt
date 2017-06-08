require 'simplecov'
SimpleCov.start do
  add_filter 'spec/'
end

require 'rspec'
require 'rack/test'
require 'rack/jwt'
require 'byebug'

RSpec.configure do |conf|
  conf.include Rack::Test::Methods
end
