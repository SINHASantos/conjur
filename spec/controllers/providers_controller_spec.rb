# frozen_string_literal: true

require 'spec_helper'

describe ProvidersController, type: :request do
  before do
    Slosilo["authn:rspec"] ||= Slosilo::Key.new
    Role.find_or_create(role_id: 'rspec:user:admin')
  end

  describe 'query param validation' do
    # Regression: valid requests should never be blocked by query param validation.
    let(:query_param_request_env) do
      token_auth_header(role: Role.find_or_create(role_id: 'rspec:user:admin'))
    end

    it 'does not reject GET /authn/:account/providers with no query params' do
      get '/authn/rspec/providers', env: query_param_request_env
      expect(response).not_to have_http_status(:unprocessable_content)
    end

    it 'rejects an unknown query param in strict mode and tolerates it otherwise' do
      get '/authn/rspec/providers?badParam=true',
        env: query_param_request_env
      expect_unknown_query_param_result(response)
    end
  end
end
