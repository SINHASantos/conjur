# frozen_string_literal: true

def strict_query_params_enabled?
  Rails.application.config.respond_to?(:feature_flags) &&
    Rails.application.config.feature_flags.enabled?(:strict_params)
end

def expect_unknown_query_param_result(
  response,
  strict: strict_query_params_enabled?
)
  if strict
    expect(response).to have_http_status(:unprocessable_content)
    expect(response.body).to include('badParam')
  else
    expect(response).not_to have_http_status(:unprocessable_content)
  end
end
