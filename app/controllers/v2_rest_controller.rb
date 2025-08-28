# frozen_string_literal: true

class V2RestController < RestController
  include APIValidator
  include Domain
  include LoggingConcern
  include Validation

  API_V2_HEADER = 'application/x.secretsmgr.v2beta+json'
  URL_REQUIRED_PARAMS = %i[account].freeze
  URL_REQUIRED_PARAMS_IDFR = (URL_REQUIRED_PARAMS + [:identifier]).freeze
  URL_REQUIRED_PARAMS_PATH = (URL_REQUIRED_PARAMS_IDFR + [:kind, :id]).freeze

  before_action :validate_header, :log_debug_requested
  after_action :update_response_header, :log_debug_finished

  def initialize(
    *args,
    branch_service: Branches::BranchService.instance,
    logger: Rails.logger,

    **kwargs
  )
    super(*args, **kwargs)

    @branch_service = branch_service
    @logger = logger
  end

  def path_identifier
    request.params[:identifier]
  end

  def update_response_header
    response.headers['Content-Type'] = request.headers['Accept'] || API_V2_HEADER
  end

  def permit_url_params(required_params = [], optional_params = [])
    req_params = request.parameters
    req_params.delete(:controller)
    req_params.delete(controller_name.singularize.to_s)
    @permit_url_params ||= handle_parameters(required_params,
                                             optional_params,
                                             url_params_keys,
                                             req_params)
  end

  def permit_body_params(required_params = [], optional_params = [])
    raise ApplicationController::BadRequestWithBody, 'Empty request body' if body_payload.empty?

    @permit_body_params ||= handle_parameters(required_params,
                                              optional_params,
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

  def read_and_auth_parent_branch(action, identifier)
    branch_identifier = parent_of(identifier)
    @branch_service.read_and_auth_branch(current_user, action, account, branch_identifier)
  end

  def read_and_auth_branch(action, identifier)
    @branch_service.read_and_auth_branch(current_user, action, account, identifier)
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

  def handle_parameters(required_params, optional_params, params_keys, parameters)
    pwr = Wrappers::ParametersWithRise.new(parameters)
    allowed_params = required_params.union(optional_params)
    return pwr.permit if allowed_params.empty?

    pwrp = pwr.permit(*allowed_params)

    required_params.each do |rpk|
      pwrp.require(rpk)
    end

    # required_params.each do |rpk|
    #   pwrp.require(rpk) && next if rpk.is_a?(String) or rpk.is_a?(Symbol)
    #
    #   if rpk.is_a?(Hash)
    #     rpk.each do |k, v|
    #       if v.is_a?(Array)
    #         v.each do |vv|
    #           r = pwr.require(k)
    #           r.first.require(vv) unless r.empty?
    #         end
    #       else
    #         pwr.require(k)&.require(v)
    #       end
    #     end
    #     next
    #   end
    #
    #   logger.warn("unsupported required param type #{rpk.class} for #{rpk}")
    # end

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
      raise ApplicationController::UnprocessableEntity, exc.message
    else
      raise exc
    end
  end
end
