# frozen_string_literal: true

require 'singleton'
require_relative '../domain'

module Workloads
  class WorkloadService
    include Singleton
    include Domain
    include Logging

    def initialize(
      authn_descriptor_service: AuthnDescriptorService.instance,
      annotation_service: Annotations::AnnotationService.instance,
      owner_service: Branches::OwnerService.instance,
      res_service: Resources::ResourceService.instance,
      membership_service: Memberships::MembershipService.instance,
      role_repo: ::Role,
      config: Rails.application.config.conjur_config,
      logger: Rails.logger
    )
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
      collect_annotations(workload).each do |a_key, a_value|
        @annotation_service.create_annotation(host_id, a_key, a_value, policy_id)
      end

      # add to authenticators groups
      workload.authn_descriptors.each do |ad|
        @authn_descriptor_service.add_descriptor_to_authenticators_group(role, account, host_res, ad)
      end

      # result
      workload_as_json(host_role, owner_id, workload)
    end

    def delete_workload(role, account, branch_identifier, workload_name)
      log_debug("role.id = #{role.id}", account:, branch_identifier:, workload_name:)

      # Construct identifiers
      host_id = full_id(account, 'host', to_identifier(branch_identifier, workload_name))
      log_debug(host_id:)

      # Fetch host resource to verify existence
      @res_service.get_res(account, 'host', to_identifier(branch_identifier, workload_name))

      log_debug("Starting recursive deletion for: #{host_id}")

      # Recursively delete the workload and all owned resources
      delete_resource_recursively!(host_id, role, Set.new)

      log_debug("Successfully deleted workload: #{host_id}")
    rescue Sequel::ForeignKeyConstraintViolation
      raise Exceptions::Forbidden.new("Cannot delete workload due to existing dependencies")
    end

    private

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

    def workload_as_json(host_role, owner_id, workload)
      owner = Branches::Owner.from_model_id(owner_id).as_json
      authn_descriptors = @authn_descriptor_service
                            .format_authn_descriptors(host_role, workload.authn_descriptors)

      workload.as_json
              .merge({ owner:, authn_descriptors: })
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
        raise ApplicationController::UnprocessableEntity,
              "Invalid IP address or CIDR range '#{addr}'"
      end
    end

    def check_restricted_to_size(cidr_arr)
      max_restricted_to = @config.max_restricted_to
      if cidr_arr.length > max_restricted_to
        raise ApplicationController::UnprocessableEntity,
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

  end
end
