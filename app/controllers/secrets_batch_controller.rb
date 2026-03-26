# frozen_string_literal: true

class SecretsBatchController < V2RestController

  BATCH_QUERY_PARAMS = [:encode_values].freeze
  BATCH_REQUIRED_PARAMS = %i[ids].freeze
  BATCH_OPTIONAL_PARAMS = [{ ids: [] }, :encode_values, { v2_secret: {} }].freeze

  validate_query_params :batch_read_values, %i[encode_values]

  def initialize(
    *args,
    secret_service: Secrets::SecretsBatchService.instance,
    **kwargs
  )
    super(*args, **kwargs)

    @secret_service = secret_service
  end

  def batch_read_values
    log_debug(body_str:)

    url_params = permit_url_params(URL_REQUIRED_PARAMS, BATCH_QUERY_PARAMS)
    input = permit_body_params(BATCH_REQUIRED_PARAMS, BATCH_OPTIONAL_PARAMS)
    log_debug(url_params:, input:)

    secrets_batch = Secrets::SecretsBatch.new(**url_params.merge(input))
    log_debug(secrets_batch:)

    response = read_batch(secrets_batch)
    log_debug("response secrets size = #{response[:secrets].size}")

    render(json: response, status: :multi_status)
    audit_success('fetch-secrets', :fetch, path_identifier, audit_payload)
  rescue => e
    audit_failure('fetch-secrets', :fetch, path_identifier, e.message, audit_payload)
    if empty_req_string_exc?(e)
      raise ApplicationController::UnprocessableContent.new, e.message
    end
    handle_exception(e)
  end

  private

  def empty_req_string_exc?(e)
    e.is_a?(ApplicationController::BadRequestWithBody) &&
      e.message.start_with?('Empty request body')
  end

  def read_batch(secrets_batch)
    @secret_service.read_batch(current_user, account, secrets_batch)
  end
end
