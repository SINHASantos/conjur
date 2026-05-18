# frozen_string_literal: true

require 'spec_helper'

describe CertificateAuthorityController, type: :request do
  before do
    Slosilo["authn:rspec"] ||= Slosilo::Key.new
    Role.find_or_create(role_id: 'rspec:user:admin')
  end

  describe 'query param validation' do
    # Regression: valid requests should never be blocked by query param validation.
    let(:query_param_request_env) do
      token_auth_header(role: Role.find_or_create(role_id: 'rspec:user:admin'))
    end

    context 'sign (no query params; account is a path segment; csr/ttl arrive in the body)' do
      it 'permits requests with no query params' do
        post '/ca/rspec/my-ca/sign', env: query_param_request_env
        expect(response).not_to have_http_status(:unprocessable_content)
      end

      it 'rejects an unknown query param in strict mode and tolerates it otherwise' do
        post '/ca/rspec/my-ca/sign?badParam=true',
          env: query_param_request_env
        expect_unknown_query_param_result(response)
      end
    end
  end
end
