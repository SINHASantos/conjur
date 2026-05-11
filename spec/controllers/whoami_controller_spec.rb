# frozen_string_literal: true

require 'spec_helper'

describe WhoamiController, type: :request do
  let(:whoami_username) { 'alice' }

  def with_strict_query_params_for_whoami
    previous_flags = Rails.application.config.feature_flags
    previous_allowlist = WhoamiController.send(:_default_query_param_allowlist)&.dup || { allowed: [] }
    allowed = previous_allowlist.fetch(:allowed, [])

    allow(previous_flags).to receive(:enabled?).with(:strict_params).and_return(true)
    WhoamiController.validate_query_params(Array(allowed))

    yield
  ensure
    WhoamiController.instance_variable_set(:@_default_query_param_allowlist, previous_allowlist)
    allow(previous_flags).to receive(:enabled?).with(:strict_params).and_call_original
  end

  describe 'query param validation' do
    # Regression: valid requests should never be blocked by query param validation.
    it 'does not reject GET /whoami with no query params' do
      get '/whoami', env: { 'HTTP_AUTHORIZATION' => access_token_for(whoami_username) }
      expect(response).not_to have_http_status(:unprocessable_content)
    end

    context 'when strict_params feature flag is enabled' do
      it 'rejects unknown query params' do
        with_strict_query_params_for_whoami do
          get '/whoami?badParam=true', env: { 'HTTP_AUTHORIZATION' => access_token_for(whoami_username) }
          expect(response).to have_http_status(:unprocessable_content)
          expect(response.body).to include('badParam')
        end
      end
    end
  end
end
