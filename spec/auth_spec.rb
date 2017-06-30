require 'spec_helper'

describe Rack::JWT::Auth do
  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:verify)  { true }
  let(:payload) { { foo: 'bar' } }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  let(:app) do
    Rack::JWT::Auth.new(inner_app, secret: secret)
  end

  describe 'initialization of' do
    describe 'secret' do
      describe 'with only secret: arg provided' do
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret) }
        it 'succeeds' do
          expect(app.secret).to eq(secret)
        end
      end

      describe 'with no secret: arg provided' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, {}) }.to raise_error(ArgumentError)
        end
      end

      describe 'with secret: arg of invalid type' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: []) }.to raise_error(ArgumentError)
        end
      end

      describe 'with nil secret: arg provided' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: nil) }.to raise_error(ArgumentError)
        end
      end

      describe 'with empty secret: arg provided' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: '') }.to raise_error(ArgumentError)
        end
      end

      describe 'with spaces secret: arg provided' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: '     ') }.to raise_error(ArgumentError)
        end
      end
    end

    describe 'verify' do
      describe 'with true arg' do
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: true) }

        it 'succeeds' do
          header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
          get('/')
          expect(last_response.status).to eq 200
        end
      end

      describe 'with false arg' do
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: false) }

        it 'succeeds' do
          header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
          get('/')
          expect(last_response.status).to eq 200
        end
      end

      describe 'with a bad arg' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: secret, verify: "badStringArg") }.to raise_error(ArgumentError)
        end
      end
    end

    describe 'options' do
      describe 'when algorithm "none" and secret is nil and verify is false' do
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: nil, verify: false, options: { algorithm: 'none' }) }

        it 'succeeds' do
          header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
          get('/')
          expect(last_response.status).to eq 200
        end
      end

      it 'raises an exception when algorithm "none" and secret not nil but verify is false' do
        args = { secret: secret, verify: false, options: { algorithm: 'none' } }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end

      it 'raises an exception when algorithm "none" and secret is nil but verify not false' do
        args = { secret: nil, verify: true, options: { algorithm: 'none' } }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end

      it 'raises an exception when invalid algorithm provided' do
        args = { secret: secret, verify: true, options: { algorithm: 'badalg' } }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end
    end

    # see also exclusion_spec.rb
    describe 'exclude' do
      it 'raises an exception when a type other than Array provided' do
        args = { secret: secret, exclude: {} }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end

      it 'raises an exception when Array contains non-String elements' do
        args = { secret: secret, exclude: ['/foo', nil, '/bar'] }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end

      it 'raises an exception when Array contains empty String elements' do
        args = { secret: secret, exclude: ['/foo', '', '/bar'] }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end

      it 'raises an exception when Array contains elements that do not start with a /' do
        args = { secret: secret, exclude: ['/foo', 'bar', '/baz'] }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end
    end

    describe 'include' do
      it 'raises an exception when a type other than Array provided' do
        args = { secret: secret, include: {} }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end

      it 'raises an exception when Array contains non-String elements' do
        args = { secret: secret, include: ['/foo', nil, '/bar'] }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end

      it 'raises an exception when Array contains empty String elements' do
        args = { secret: secret, include: ['/foo', '', '/bar'] }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end

      it 'raises an exception when Array contains elements that do not start with a /' do
        args = { secret: secret, include: ['/foo', 'bar', '/baz'] }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end
    end

    it 'raises an exception when given an include and exclude' do
      args = { secret: secret, include: ['/foo'], exclude: ['/bar'] }
      expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
    end
  end

  describe 'when given excluded paths' do
    let (:app) { Rack::JWT::Auth.new(inner_app, { secret: secret, exclude: ['/foo', '/bar'] }) }

    it 'should authorize given paths without a valid token' do
      get('/foo')
      expect(last_response.status).to eq 200

      get('/bar')
      expect(last_response.status).to eq 200
    end

    it 'should forbid other paths without a valid token' do
      get('/')
      expect(last_response.status).to eq 401
    end
  end

  describe 'when given included paths' do
    let (:app) { Rack::JWT::Auth.new(inner_app, { secret: secret, include: ['/foo', '/bar'] }) }

    it 'should forbid given paths without a valid token' do
      get('/foo')
      expect(last_response.status).to eq 401

      get('/bar')
      expect(last_response.status).to eq 401
    end

    it 'should authorize other paths without a valid token' do
      get('/')
      expect(last_response.status).to eq 200
    end
  end


  describe 'authorized roles' do
    describe 'initilization' do
      it 'raises an exception with invalid argument' do
        args = { secret: secret, authorized_roles: 'foo' }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)

        args = { secret: secret, authorized_roles: [''] }
        expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
      end
    end

    describe 'token verification with one role' do
      let(:app) { Rack::JWT::Auth.new(inner_app, { secret: secret, authorized_roles: ['myrole'] }) }

      it 'refuses access when payload has no role' do
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
      end

      it 'refuses access when payload role is not a string' do
        payload = { role: { foo: 'bar'} }
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
      end

      it 'refuses access when payload has a mismatch role' do
        payload = { role: 'another_role' }
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
      end

      it 'gives access to an authorized role' do
        payload = { role: 'myrole' }
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
      end
    end

    describe 'token verification with several roles' do
      let(:app) { Rack::JWT::Auth.new(inner_app, { secret: secret, authorized_roles: ['myrole1', 'myrole2'] }) }

      it 'refuses access when payload has no role' do
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
      end

      it 'refuses access when payload role is not a string' do
        payload = { role: { foo: 'bar'} }
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
      end

      it 'refuses access when payload has a mismatch role' do
        payload = { role: 'another_role' }
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
      end

      it 'gives access to an authorized role' do
        payload = { role: 'myrole1' }
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
      end
    end
  end
end
