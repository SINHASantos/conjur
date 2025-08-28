# frozen_string_literal: true

require 'singleton'
require_relative '../domain'

module Workloads
  class AuthnDescriptorService
    include Singleton
    include Domain
    include Logging

    def initialize(
      annotation_service: Annotations::AnnotationService.instance,
      res_service: Resources::ResourceService.instance,
      membership_service: Memberships::MembershipService.instance,
      branch_service: Branches::BranchService.instance,
      logger: Rails.logger
    )
      @annotation_service = annotation_service
      @res_service = res_service
      @membership_service = membership_service
      @branch_service = branch_service
      @logger = logger
    end

    def add_descriptor_to_authenticators_group(role, account, member_res, descriptor)
      return if descriptor.api_key?

      begin
        # check_permission_for_group_update(role, account, descriptor.branch)
        descriptor_branch = make_branch_identifier(descriptor.type, descriptor.service_id)
        check_permission_for_group_update(role, account, descriptor_branch)

        # Get group resource without permission check
        group_identifier = "#{descriptor_branch}/apps"
        group_res = @res_service.get_res(account, 'group', group_identifier)

        # grant membership to the authenticator group
        @membership_service.check_membership_not_exist(group_res, member_res)
        @membership_service.create_membership_db(group_res, member_res)
      rescue ApplicationController::Forbidden
        raise Errors::Authentication::Security::MissingAuthenticatorsPermissions,
              'conjur:policy:' + branch
      end
    end

    def format_authn_descriptors(host_role, authn_descriptors)
      authn_descriptors.map do |authn_desc|
        if authn_desc.api_key?
          enhance_api_key_data(host_role.api_key, authn_desc.as_json)
        else
          authn_desc.as_json
        end
      end
    end

    def collect_authn_descriptors_annotations(authn_descriptors)
      authn_descriptors.each_with_object({}) do |descriptor, annotations|
        if descriptor.api_key?
          annotations["authn/api-key"] = "true"
          next
        end

        annotations.merge!(collect_not_api_key_descriptor_annotations(descriptor))
      end
    end

    private

    def make_branch_identifier(type, service_id)
      auth_branch = branch_identifier_from_type(type)
      return auth_branch if type == 'gcp'

      service_id.empty? ? auth_branch : "#{auth_branch}/#{service_id}"
    end

    def branch_identifier_from_type(type)
      branch_name = branch_name_from_type(type)
      "conjur/#{branch_name}"
    end

    def branch_name_from_type(type)
      { "aws" => "authn-iam",
        "cert" => "authn-cert"
      }.fetch(type, "authn-#{type}")
    end

    def enhance_api_key_data(api_key, desc_as_json)
      # enhance api_key descriptor data with generated api key value
      desc_as_json.merge({ 'data' => desc_as_json['data'] || {} })
                  .tap { |h| h['data']['value'] = api_key }
    end

    def check_permission_for_group_update(role, account, branch_identifier)
      @branch_service.read_and_auth_branch(role, :create, account, branch_identifier)
    end

    def collect_not_api_key_descriptor_annotations(descriptor)
      authn_branch = branch_name_from_type(descriptor.type)
      authn_path = if descriptor.type?(AuthnDescriptor::JWT)
                     "#{authn_branch}/#{descriptor.service_id}"
                   else
                     authn_branch
                   end

      annotations = {}
      # Process data fields into annotations
      descriptor.data.each do |key, value|
        ann_key = key.to_s
        unless [AuthnDescriptor::JWT, AuthnDescriptor::AWS].include?(descriptor.type)
          ann_key = ann_key.tr('_', '-') # fix annotation key format
        end

        authn_key = "#{authn_path}/#{ann_key}"
        authn_value = ann_value_for_cert_san_data(descriptor, key, value)
        annotations[authn_key] = authn_value
      end
      annotations
    end

    def ann_value_for_cert_san_data(descriptor, key, value)
      if cert_san_data_array?(descriptor, key, value)
        # for arrays, join values with comma to a string
        value.join(", ")
      else
        value.to_s
      end
    end

    def cert_san_data_array?(descriptor, annotation_key, value)
      descriptor.type?(AuthnDescriptor::CERT) &&
        Validating::AuthnDescriptorCertValidation::SAN_DATA_STR_KEYS.include?(annotation_key) &&
        value.is_a?(Array)
    end
  end
end
