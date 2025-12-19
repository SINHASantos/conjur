# frozen_string_literal: true

class WorkloadsController < V2RestController

  WORKLOAD_REQUIRED_PARAMS = %i[name branch authn_descriptors].freeze

  WORKLOAD_OPTIONAL_PARAMS = [:name, :branch, :type, :subtype,
                              owner: [:kind, :id],
                              annotations: {},
                              authn_descriptors: [[:type, :service_id, data: {}]]].freeze

  WORKLOAD_OPTIONAL_RESTRICTED_TO_PARAMS = [restricted_to: []]

  def initialize(
    *args,
    workload_service: Workloads::WorkloadService.instance,
    owner_service: Branches::OwnerService.instance,
    config: Rails.application.config.conjur_config,
    **kwargs
  )
    super(*args, **kwargs)

    @workload_service = workload_service
    @owner_service = owner_service
    @config = config
  end

  def create
    log_debug(body_str:)

    url_params = permit_create_url_params
    input = permit_create_body_params
    log_debug(url_params:, input:)

    workload = Workloads::Workload.new(**input)
    log_debug(workload:)

    authorize_create_in_parent(workload)
    # check_workload_not_exists(workload)
    check_owner_exists_if_set(workload)

    render(json: create_workload(workload), status: :created)
    audit_success('workload', :create, path_identifier, audit_payload)
  rescue => e
    audit_failure('workload', :create, path_identifier, e.message, audit_payload)
    handle_exception(e)
  end

  def destroy
    log_debug("Deleting workload: #{path_identifier}")

    url_params = permit_destroy_url_params
    log_debug(url_params:)

    branch_identifier, workload_name = parse_workload_identifier(path_identifier)
    log_debug(branch_identifier:, workload_name:)

    authorize_delete_in_parent(branch_identifier)

    delete_workload(branch_identifier, workload_name)

    head :no_content
    audit_success('workload', :delete, path_identifier)
  rescue => e
    audit_failure('workload', :delete, path_identifier, e.message)
    handle_exception(e)
  end

  private

  def permit_create_url_params
    permit_url_params(URL_REQUIRED_PARAMS)
  end

  def permit_destroy_url_params
    permit_url_params(URL_REQUIRED_PARAMS_IDFR)
  end

  def parse_workload_identifier(identifier)
    # Parse the identifier in the format "branch/workload-name"
    # The branch itself can contain slashes
    parts = identifier.split('/')

    raise ApplicationController::InvalidParameter, "Invalid workload identifier format" if parts.length < 2

    workload_name = res_name(identifier)
    branch_identifier = parent_of(identifier)

    [branch_identifier, workload_name]
  end

  def restricted_ip_enabled?
    @restricted_ip_enabled ||= @config.try(:conjur_restricted_ip_enabled)
  end

  def permit_create_body_params
    optional_params = manage_restricted_ip_enabled(WORKLOAD_OPTIONAL_PARAMS)
    log_debug(optional_params:)

    permit_body_params(WORKLOAD_REQUIRED_PARAMS, optional_params)
  end

  private

  def manage_restricted_ip_enabled(params)
    restricted_ip_enabled? ? params.union(WORKLOAD_OPTIONAL_RESTRICTED_TO_PARAMS) : params
  end

  def authorize_create_in_parent(workload)
    read_and_auth_branch(:create, workload.branch)
  end

  def authorize_delete_in_parent(branch_identifier)
    read_and_auth_branch(:update, branch_identifier)
  end

  def check_workload_not_exists(workload)
    @workload_service.check_workload_not_exists(account, workload)
  end

  def create_workload(workload)
    @workload_service.create_workload(current_user, account, workload)
  end

  def delete_workload(branch_identifier, workload_name)
    @workload_service.delete_workload(current_user, account, branch_identifier, workload_name)
  end

  def check_owner_exists_if_set(workload)
    return unless workload.owner.set?

    @owner_service.check_owner_exists(account, workload.owner)
  end
end