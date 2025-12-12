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
      role_repo: ::Role,
      config: Rails.application.config.conjur_config,
      logger: Rails.logger
    )
      @authn_descriptor_service = authn_descriptor_service
      @annotation_service = annotation_service
      @owner_service = owner_service
      @res_service = res_service
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

    private

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
