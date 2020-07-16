require 'spec_helper'

describe Rack::JWT::Auth do
  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:verify)  { true }
  let(:payload) { { foo: 'bar' } }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret) }

  describe 'when handling exlusions' do
    describe 'passes through matching exact path' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: ['/static']) }

      it 'returns a 200' do
        get('/static')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching exact path with trailing slash' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: ['/static']) }

      it 'returns a 200' do
        get('/static/')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching exact path with sub-path' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: ['/static']) }

      it 'returns a 200' do
        get('/static/foo/bar')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching path with multiple exclusions' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: %w(/docs /books /static)) }

      it 'returns a 200' do
        get('/static/foo/bar')
        expect(last_response.status).to eq 200
      end
    end

    describe 'checks for both HTTP method and path' do
      context 'when the argument is a symbol' do 
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: [['/static', :get]]) }

        it 'returns a 200 when method is matches' do
          get('/static')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 when method does not match' do
          post('/static')
          expect(last_response.status).to eq 401
        end
      end

      context 'when the argument is a pattern' do 
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: [['/static', 'get|put']]) }

        it 'returns a 200 when method is matches' do
          get('/static')
          expect(last_response.status).to eq 200

          put('/static')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 when method does not match' do
          post('/static')
          expect(last_response.status).to eq 401
        end
      end

      context 'when the argument contains uppercase letters' do 
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: [['/static', 'gEt']]) }

        it 'matches http method in case insensitive mode' do
          get('/static')
          expect(last_response.status).to eq 200
        end
      end
    end

    describe 'fails when no matching path and no token' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: %w(/docs /books /static)) }

      it 'returns a 401' do
        get('/somewhere')
        expect(last_response.status).to eq 401
      end
    end
  end

  describe 'when handling exclusions via "optional"' do
    describe 'passes through matching exact path' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, optional: ['/static']) }

      context 'when path mathes' do
        it 'returns a 200 if header is missing' do
          get('/static')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 if the header is bad' do
          header 'Authorization', "Bearer I'm not that bad of a header. Let me in please."
          get('/static')
          expect(last_response.status).to eq 401
        end

        it 'returns a 200 if the header is good' do
          header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
          get('/static')
          expect(last_response.status).to eq 200
        end
      end
    end

    describe 'checks for both HTTP method and path' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, optional: [['/static', :get]]) }

      it 'returns a 200 when method is matches' do
        get('/static')
        expect(last_response.status).to eq 200
      end

      it 'returns a 401 when method does not match' do
        post('/static')
        expect(last_response.status).to eq 401
      end
    end

    describe 'fails when no matching path and no token' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, optional: %w(/docs /books /static)) }

      it 'returns a 401' do
        get('/somewhere')
        expect(last_response.status).to eq 401
      end
    end
  end
end
