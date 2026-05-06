# frozen_string_literal: true

class V2RestController < RestController
  include APIValidator
  include Domain
  include LoggingConcern
  include Validation

  API_V2_BETA_HEADER = 'application/x.secretsmgr.v2beta+json'
  URL_REQUIRED_PARAMS = %i[account].freeze
  URL_REQUIRED_PARAMS_IDFR = (URL_REQUIRED_PARAMS + [:identifier]).freeze
  URL_REQUIRED_PARAMS_PATH = (URL_REQUIRED_PARAMS_IDFR + [:kind, :id]).freeze

  # V2 controllers declare strict query-param allowlists via validate_query_params
  # (strict mode by default). check_query_params runs before actions and rejects
  # unknown query params early. Actions then use permit_url_params / permit_body_params
  # to enforce required/allowed params and extract values.

  before_action :validate_header, :log_debug_requested
  after_action :update_response_header, :log_debug_finished

  def initialize(
    *args,
    auth_service: Authorisation::AuthorisationService.instance,
    logger: Rails.logger,

    **kwargs
  )
    super(*args, **kwargs)
    @auth_service = auth_service
    @logger = logger
  end

  def path_identifier
    request.params[:identifier]
  end

  def update_response_header
    response.headers['Content-Type'] = request.headers['Accept'] || API_V2_BETA_HEADER
  end

  def permit_url_params(required_params = [], allowed_params = [])
    req_params = request.parameters
    req_params.delete(:controller)
    req_params.delete(controller_name.singularize.to_s)
    @permit_url_params ||= handle_parameters(required_params,
                                             allowed_params,
                                             url_params_keys,
                                             req_params)
  end

  def permit_body_params(required_params = [], allowed_params = [])
    raise ApplicationController::BadRequestWithBody, 'Empty request body' if body_str.empty?

    @permit_body_params ||= handle_parameters(required_params,
                                              allowed_params,
                                              body_params_keys,
                                              body_payload)
  end

  def body_payload
    @body_payload ||= begin
                        JSON.parse(body_str, symbolize_names: true)
                      rescue JSON::ParserError => e
                        raise ApplicationController::BadRequestWithBody, "Invalid JSON body: #{e.message}"
                      end
  end

  def body_str
    @body_str ||= request.body.read
  end

  def account
    @account ||= permit_url_params[:account]
  end

  def auth_action_in_branch(action, identifier)
    @auth_service.auth_action(current_user, action, account, 'policy', identifier, 'branch')
  end

  def auth_create_or_up_in_branch(identifier)
    @auth_service.auth_create_or_up_in_branch(current_user, account, identifier)
  end

  def auth_create_or_up(kind, identifier, kind_for_error = nil)
    @auth_service.auth_create_or_up(current_user, account, kind, identifier, kind_for_error)
  end

  def auth_any_actions(actions, kind, identifier, kind_for_error = nil)
    @auth_service.auth_any_actions(current_user, actions, account, kind, identifier, kind_for_error)
  end

  def auth_action(action, kind, identifier, kind_for_error = nil)
    @auth_service.auth_action(current_user, action, account, kind, identifier, kind_for_error)
  end

  def can_action?(action, kind, res_id)
    @auth_service.can_action?(current_user, action, kind, res_id)
  end

  def audit_payload
    # need to have one line string in audit log
    @body_payload.nil? ? @body_str&.gsub(/\s+/, ' ')&.strip : JSON.generate(body_payload)
  end

  def audit_success(resource_type, operation, resource_identifier, body_json_str = nil)
    audit_event(operation.to_s, resource_type.to_s, resource_identifier, body_json_str, nil)
  end

  def audit_failure(resource_type, operation, resource_identifier, failure_message, body_json_str = nil)
    audit_event(operation.to_s, resource_type.to_s, resource_identifier, body_json_str, failure_message)
  end

  private

  # parameters
  def url_params_keys
    @url_params_keys ||= request.parameters.keys.map(&:to_sym)
  end

  def body_params_keys
    body_payload.keys.map(&:to_sym)
  end

  def handle_parameters(required_params, allowed_params, params_keys, parameters)
    pwr = Wrappers::ParametersWithRise.new(parameters)
    all_allowed_params = required_params.union(allowed_params)
    return pwr.to_hash.deep_symbolize_keys if all_allowed_params.empty?

    pwr.require(required_params)
    pwrp = pwr.permit(*all_allowed_params)

    pwrp.to_hash.deep_symbolize_keys
  rescue ActionController::UnpermittedParameters => e
    raise ApplicationController::InvalidParameter, "Unexpected parameters: #{e.params.join(', ')}"
  rescue ActionController::ParameterMissing
    missing_params = required_params - params_keys
    raise Errors::Conjur::ParameterMissing, missing_params.join(', ')
  end

  # audit

  def audit_event(operation, resource_type, resource_identifier, body_json_str, failure_message)
    Audit.logger.log(
      Audit::Event::V2Resource.new(
        operation: operation,
        resource_type: resource_type,
        resource_name: resource_identifier,
        request_path: request.path,
        request_body: body_json_str,
        user: current_user.role_id,
        client_ip: request.ip,
        error_message: failure_message&.gsub(/\s+/, ' ')&.strip
      )
    )
  end

  # exceptions handling

  def handle_exception(exc)
    log_error(exc)

    case exc
    when DomainValidationError
      raise ApplicationController::UnprocessableContent, exc.message
    else
      raise exc
    end
  end
end
