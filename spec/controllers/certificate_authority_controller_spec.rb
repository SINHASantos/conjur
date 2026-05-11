# frozen_string_literal: true

require 'spec_helper'

describe CertificateAuthorityController, type: :request do
  describe 'query param validation' do
    # Regression: valid requests should never be blocked by query param validation.
    context 'sign (no query params; account is a path segment; csr/ttl arrive in the body)' do
      it 'permits requests with no query params' do
        post '/ca/rspec/my-ca/sign'
        expect(response).not_to have_http_status(:unprocessable_content)
      end
    end
  end
end
