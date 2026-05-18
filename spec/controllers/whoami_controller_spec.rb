# frozen_string_literal: true

require 'spec_helper'

describe WhoamiController, type: :request do
  let(:whoami_username) { 'alice' }

  describe 'query param validation' do
    # Regression: valid requests should never be blocked by query param validation.
    it 'does not reject GET /whoami with no query params' do
      get '/whoami', env: { 'HTTP_AUTHORIZATION' => access_token_for(whoami_username) }
      expect(response).not_to have_http_status(:unprocessable_content)
    end

    it 'rejects an unknown query param in strict mode and tolerates it otherwise' do
      get '/whoami?badParam=true', env: { 'HTTP_AUTHORIZATION' => access_token_for(whoami_username) }
      expect_unknown_query_param_result(response)
    end
  end
end
