# frozen_string_literal: true

require 'singleton'
require_relative '../domain'

module Workloads
  class AuthnDescriptorService
    include Singleton
    include Domain
    include Logging

    AUTHN_API_KEY_ANNS = 'authn/api-key'
    AUTHN_ANNS_PREFIX = 'authn-'
    AUTHN_CERT_ANNS_DATA_KEYS = %w[san-ip san-dns san-uri].freeze

    def initialize(
      annotation_service: Annotations::AnnotationService.instance,
      res_service: Resources::ResourceService.instance,
      membership_service: Memberships::MembershipService.instance,
      auth_service: Authorisation::AuthorisationService.instance,
      logger: Rails.logger
    )
      @annotation_service = annotation_service
      @res_service = res_service
      @membership_service = membership_service
      @auth_service = auth_service
      @logger = logger
    end

    def add_descriptor_to_authenticators_group(role, account, member_res, descriptor)
      # For api-key we don't add to any group
      return if descriptor.api_key?

      begin
        descriptor_branch = descriptor.branch_path
        check_can_create_or_up_in_branch(role, account, descriptor_branch)

        # Get group resource without permission check
        group_identifier = "#{descriptor_branch}/apps"
        group_res = @res_service.get_res(account, 'group', group_identifier)

        # grant membership to the authenticator group
        @membership_service.check_membership_not_exist(group_res, member_res)
        @membership_service.create_membership_db(group_res, member_res)
      rescue ApplicationController::Forbidden
        raise Errors::Authentication::Security::MissingAuthenticatorsPermissions,
              'conjur:policy:' + descriptor_branch
      end
    end

    def collect_authn_descriptors_annotations(authn_descriptors)
      authn_descriptors.each_with_object({}) do |descriptor, annotations|
        if descriptor.api_key?
          annotations[AUTHN_API_KEY_ANNS] = "true"
          next
        end

        annotations.merge!(collect_not_api_key_descriptor_annotations(descriptor))
      end
    end

    def regain_authn_desc_views(account, host_res_id, authn_desc_anns, api_key, show_api_key)
      memberships = ::RoleMembership
                      .select(:role_id, :member_id)
                      .where(member_id: host_res_id, ownership: false)
                      .where(Sequel.like(:role_id, "#{account}:group:conjur/authn%"))
                      .where(Sequel.like(:role_id, "%apps%"))
                      .all

      remaining_authn_desc_anns = authn_desc_anns
      authn_desc_views = memberships.map do |m|
        role_id = m.values[:role_id]
        branch_type = role_id.split("/")
                             .find { |part| part.start_with?(AUTHN_ANNS_PREFIX) }

        next if branch_type.nil?

        type = Authenticators::TypeConverter.get_type_from_branch(branch_type)
        service_id = regain_service_id(type, role_id)

        anns_key_prefix = "#{branch_type}/"
        data_anns, not_data_anns = remaining_authn_desc_anns.partition { |key, _| key.start_with?(anns_key_prefix) }
        remaining_authn_desc_anns = not_data_anns.to_h

        data = data_anns.each_with_object({}) do |(key, value), result|
          normalized_key = normalize_authn_data_key(key, anns_key_prefix, type, service_id)

          result[normalized_key] = if cert_array_ann_key?(type, normalized_key)
                                     parse_ann_value(value)
                                   else
                                     value
                                   end
        end

        if data.empty?
          { type:, service_id: }
        else
          { type:, service_id:, data: }
        end
      end

      if remaining_authn_desc_anns.key?(AUTHN_API_KEY_ANNS) && remaining_authn_desc_anns[AUTHN_API_KEY_ANNS] == "true"
        if show_api_key
          authn_desc_views << { type: AuthnDescriptor::API_KEY, data: { value: api_key } }
        else
          authn_desc_views << { type: AuthnDescriptor::API_KEY }
        end
        remaining_authn_desc_anns.delete(AUTHN_API_KEY_ANNS)
      end

      authn_desc_views
    end

    def regain_service_id(type, role_id)
      return "default" if type == AuthnDescriptor::GCP
      role_id.split("/")[-2]
    end

    private

    def enhance_api_key_data(api_key, desc_as_json)
      # enhance api_key descriptor data with generated api key value
      desc_as_json.merge({ 'data' => desc_as_json['data'] || {} })
                  .tap { |h| h['data']['value'] = api_key }
    end

    def check_can_create_or_up_in_branch(role, account, branch_identifier)
      @auth_service.auth_create_or_up_in_branch(role, account, branch_identifier)
    end

    def collect_not_api_key_descriptor_annotations(descriptor)
      authn_branch = Authenticators::TypeConverter.get_branch_from_type(descriptor.type)
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
        AuthnDescriptor::SAN_DATA_STR_KEYS.include?(annotation_key) &&
        value.is_a?(Array)
    end

    def normalize_authn_data_key(key, anns_key_prefix, type, service_id)
      normalized = key.delete_prefix(anns_key_prefix)
      if type == AuthnDescriptor::JWT
        normalized = normalized.delete_prefix("#{service_id}/")
      end

      normalized = normalized.gsub('-', '_') unless [AuthnDescriptor::JWT, AuthnDescriptor::AWS].include?(type)
      return normalized.delete_prefix("#{service_id}/") if type == JWT

      normalized
    end

    def cert_array_ann_key?(type, key)
      return false unless type == 'cert'

      AUTHN_CERT_ANNS_DATA_KEYS.include?(key.to_s.tr('_', '-'))
    end

    def parse_ann_value(value)
      return value unless value.is_a?(String)
      return value unless value.start_with?('[') && value.end_with?(']')

      JSON.parse(value)
    rescue JSON::ParserError
      value
    end
  end
end
