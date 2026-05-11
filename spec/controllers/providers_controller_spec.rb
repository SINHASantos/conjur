# frozen_string_literal: true

require 'spec_helper'

describe ProvidersController, type: :request do
  describe 'query param validation' do
    # Regression: valid requests should never be blocked by query param validation.
    it 'does not reject GET /authn/:account/providers with no query params' do
      get '/authn/rspec/providers'
      expect(response).not_to have_http_status(:unprocessable_content)
    end
  end
end
