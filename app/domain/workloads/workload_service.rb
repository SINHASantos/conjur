# frozen_string_literal: true

require 'singleton'
require_relative '../domain'

module Workloads
  class WorkloadService
    include Singleton
    include Domain
    include Logging

    AUTHN_ANNS_PREFIX = 'authn-'
    AUTHN_API_KEY_ANNS = 'authn/api-key'
    TYPE_ANN_KEY = 'type'

    def initialize(
      auth_service: Authorisation::AuthorisationService.instance,
      authn_descriptor_service: AuthnDescriptorService.instance,
      annotation_service: Annotations::AnnotationService.instance,
      owner_service: Branches::OwnerService.instance,
      res_service: Resources::ResourceService.instance,
      membership_service: Memberships::MembershipService.instance,
      role_repo: ::Role,
      config: Rails.application.config.conjur_config,
      logger: Rails.logger
    )
      @auth_service = auth_service
      @authn_descriptor_service = authn_descriptor_service
      @annotation_service = annotation_service
      @owner_service = owner_service
      @res_service = res_service
      @membership_service = membership_service
      @role_repo = role_repo
      @config = config
      @logger = logger
    end

    def create_workload(role, account, workload)
      log_debug("role.id = #{role.id}", account:, workload:)

      branch_identifier = workload.branch
      policy_id = full_id(account, 'policy', branch_identifier)
      host_id = full_id(account, 'host', workload.identifier)
      owner_id = @owner_service.resource_owner_id(account, branch_identifier, workload.owner)
      log_debug(policy_id:, host_id:, owner_id:)

      # host
      host_res = @res_service.save_res(policy_id, owner_id, host_id, kind_msg: 'workload')

      # host role
      host_role = @role_repo.create(policy_id:, role_id: host_id)

      # restricted_to
      save_restricted_to(host_role, workload.restricted_to)

      # annotations
      annotations = collect_annotations(workload)
      log_debug(annotations:)
      annotations.each do |a_key, a_value|
        @annotation_service.create_annotation(host_id, a_key, a_value, policy_id)
      end

      # add to authenticators groups
      workload.authn_descriptors.each do |ad|
        @authn_descriptor_service.add_descriptor_to_authenticators_group(role, account, host_res, ad)
      end

      # result
      prepare_workload_view(account, host_res, host_role, true).as_json
    end

    def read_workload(role, account, workload_show)
      log_debug("role.id = #{role.id}", account:, workload_show:)
      identifier = workload_show.identifier
      host_res = @res_service.read_res(role, account, 'host', identifier)
      host_role = host_res.role
      prepare_workload_view(account, host_res, host_role)
    end

    def delete_workload(role, account, branch_identifier, workload_name)
      log_debug("role.id = #{role.id}", account:, branch_identifier:, workload_name:)

      # Construct identifiers
      host_id = full_id(account, 'host', to_identifier(branch_identifier, workload_name))
      log_debug(host_id:)

      # Fetch host resource to verify existence
      @res_service.check_exists(account, 'host', to_identifier(branch_identifier, workload_name))

      # Recursively delete the workload and all owned resources
      log_debug("Starting recursive deletion for: #{host_id}")
      delete_resource_recursively!(host_id, role, Set.new)

      log_debug("Successfully deleted workload: #{host_id}")
    rescue Sequel::ForeignKeyConstraintViolation
      raise Exceptions::Forbidden.new("Cannot delete workload due to existing dependencies")
    end

    private

    def prepare_workload_view(account, host_res, host_role, show_api_key = false)
      restricted_to = restricted_ip_enabled? ? host_role.restricted_to.map(&:to_s) : nil
      api_key = show_api_key ? host_role.api_key : nil
      annotations = Annotations::Annotations.from_model(host_res.annotations)
      type, subtype = regain_type_and_subtype!(annotations)

      authn_desc_anns_list, not_authn_desc_anns_list = annotations.partition do |k, _|
        k.start_with?(AUTHN_ANNS_PREFIX) ||
          k == TYPE_ANN_KEY ||
          k == AUTHN_API_KEY_ANNS
      end

      authn_desc_anns = authn_desc_anns_list.to_h
      workload_anns = not_authn_desc_anns_list.to_h
      log_debug(authn_desc_anns:, workload_anns:)

      authn_desc_views = @authn_descriptor_service
                           .regain_authn_desc_views(account,
                                                    host_res.id,
                                                    authn_desc_anns,
                                                    api_key,
                                                    show_api_key)
      log_debug(authn_desc_views:)

      workload_view(host_res.identifier,
                    type,
                    subtype,
                    host_res.owner_id,
                    authn_desc_views,
                    workload_anns,
                    restricted_to)
    end

    def workload_view(host_identifier, type, subtype, owner_id, authn_desc_views, annotations, restricted_to = nil)
      {
        name: res_name(host_identifier),
        branch: parent_of(host_identifier),
        type:,
        subtype:,
        owner: Branches::Owner.h_from_model_id(owner_id),
        annotations:,
        restricted_to:,
        authn_descriptors: authn_desc_views
      }.compact
    end

    # Recursively delete a resource and all its owned resources
    # @param record_id [String] Full resource ID
    # @param role [Role] Current user's role
    # @param visited [Set] Set of already-visited resource IDs for cycle prevention
    def delete_resource_recursively!(record_id, role, visited)
      # Prevent infinite recursion from circular ownership
      return if visited.include?(record_id)
      visited.add(record_id)

      log_debug("Processing deletion for: #{record_id}")

      # Check permission before deletion
      check_update_permission!(record_id, role)

      # Find all resources owned by this resource
      owned_resources = @res_service.find_owned_resources(record_id)
      log_debug("Found #{owned_resources.count} owned resources for #{record_id}")

      # Recursively delete each owned resource (with permission checks on each)
      owned_resources.each do |resource|
        delete_resource_recursively!(resource.resource_id, role, visited)
      end

      # Delete the resource itself (CASCADE will handle annotations, permissions)
      resource = @res_service.fetch_by_id(record_id)
      if resource
        log_debug("Deleting resource: #{record_id}")
        resource.destroy
      end

      # Delete the associated role (CASCADE will handle credentials, memberships)
      role_record = @role_repo[record_id]
      if role_record
        log_debug("Deleting role: #{record_id}")
        role_record.destroy
      end
    end

    # Check if the user has update permission on the resource
    # @param record_id [String] Full resource ID
    # @param role [Role] Current user's role
    # @raise [Exceptions::Forbidden] if user doesn't have update permission
    def check_update_permission!(record_id, role)
      resource = @res_service.fetch_by_id(record_id)
      return unless resource

      unless role.allowed_to?(:update, resource)
        raise Exceptions::Forbidden.new(
          "Insufficient permissions to delete resource '#{record_id}'. " \
            "Update permission required."
        )
      end
    end

    def save_restricted_to(host_role, restricted_to_arr)
      cidr_arr = restricted_to_arr.map { |addr| make_cidr(addr) }

      check_restricted_to_size(cidr_arr)

      host_role.restricted_to = Sequel.pg_array(cidr_arr, :cidr)
      host_role.save

      cidr_arr
    end

    def make_cidr(addr_str)
      # Normalize addresses to always include network mask e.g.:
      # 1.1.1.1 => 1.1.1.1/32, 2.2.0.0/16 => 2.2.0.0/16.
      # This normalization is necessary in order to apply proper array union
      # when deletion is not permitted.
      begin
        Conjur::CIDR.new(addr_str).to_s
      rescue IPAddr::Error
        raise ApplicationController::UnprocessableContent,
              "Invalid IP address or CIDR range '#{addr}'"
      end
    end

    def check_restricted_to_size(cidr_arr)
      max_restricted_to = @config.max_restricted_to
      if cidr_arr.length > max_restricted_to
        raise ApplicationController::UnprocessableContent,
              "Too many CIDR entries. Maximum allowed is #{max_restricted_to}"
      end
    end

    def collect_annotations(workload)
      workload.annotations
              .merge(@authn_descriptor_service.
                collect_authn_descriptors_annotations(workload.authn_descriptors))
              .merge(build_workload_type_hash(workload))
    end

    def build_workload_type_hash(workload)
      value = workload.type
      value += "/#{workload.subtype}" if workload.kube_type? && workload.subtype.present?

      { 'type' => value }
    end

    def regain_type_and_subtype!(annotations)
      type = annotations.delete('type') || Workload::DEFAULT_WORKLOAD_TYPE
      if type.start_with?("#{Validating::WorkloadValidation::KUBE_TYPE}/")
        type, subtype = type.split('/')
        return type, subtype
      end

      [type, annotations.delete('subtype')]
    end

    def restricted_ip_enabled?
      @restricted_ip_enabled ||= @config.try(:conjur_restricted_ip_enabled)
    end
  end
end
