# frozen_string_literal: true

require_relative '../../domain'
require_relative '../../validation'

module Workloads
  module Validating
    module WorkloadValidation
      extend(Domain)
      include Domain
      include Validation

      TYPES = %w[jenkins gitlab kubernetes azure_devops github_actions
                ansible terraform spring aws azure gcp mule_app ai_agent
                mcp_server bitbucket octupus virtual_machine iot_device other].freeze

      OTHER_TYPE = 'other'.freeze
      KUBE_TYPE = 'kubernetes'.freeze
      KUBE_SUBTYPE_DEFAULT = 'openshift'.freeze
      KUBE_SUBTYPES = %w[gke openshift eks aks].freeze
      KUBE_SUBTYPES_STR = KUBE_SUBTYPES.join(', ').freeze
      MAX_ANNOTATIONS_SIZE = 20
      NAME_PATTERN = /\A[a-zA-Z0-9:_{}\-.\/"]+\z/.freeze
      NAME_LENGTH_MIN = 3
      NAME_LENGTH_MAX = 120

      def type?(type)
        @type == type
      end

      def kube_type?
        type?(KUBE_TYPE)
      end

      def not_kube_type?
        !kube_type?
      end

      def in_types?
        TYPES.include?(type)
      end

      private

      def validate_branch_and_name
        if @branch && @name
          validate_identifier("Identifier(branch/name)", to_identifier(@branch, @name))
        end
      end

      def init_type(type)
        return OTHER_TYPE if type.to_s.strip.empty? # nil and blank string

        type.is_a?(String) ? type.downcase : type
      end

      def init_subtype(type, subtype)
        if type == KUBE_TYPE
          return subtype.to_s.strip.empty? ? KUBE_SUBTYPE_DEFAULT : subtype
        end

        subtype || ''
      end

      def init_owner(owner_hash)
        return Branches::Owner.new if owner_hash.nil?

        unless owner_hash.is_a?(Hash)
          errors.add(:owner, "must be a hash containing 'kind' and 'id' fields")
          return
        end

        unless owner_hash.key?(:kind) && owner_hash.key?(:id)
          errors.add(:owner, "must contain both 'kind' and 'id' fields")
        end

        begin
          Branches::Owner.new(**owner_hash)
        rescue Validation::DomainValidationError => exc
          exc.errors.each { |o_err| errors.add(:owner, o_err.message) }
        end
      end

      def init_authn_descriptors(authn_descriptors)
        unless authn_descriptors.is_a?(Array) && authn_descriptors.size == 1
          errors.add(:authn_descriptors, "must be an array with exactly one descriptor")
          return
        end

        authn_descriptors.map.with_index do |ad, idx|
          begin
            Workloads::AuthnDescriptor.new(**ad)
          rescue Validation::DomainValidationError => exc
            exc.errors.each do |ad_err|
              errors.add(:authn_descriptors, ad_err.full_message + " in authn_descriptors[#{idx}]")
            end
          end
        end
      end

      def init_annotations(annotations)
        return Annotations::Annotations.new if annotations.nil?

        return unless validate_is_class(:base, annotations, Hash,
                                        msg: "Invalid annotations parameter. Must be a dictionary.")

        if annotations.size > MAX_ANNOTATIONS_SIZE
          errors.add(:base, "Cannot have more than #{MAX_ANNOTATIONS_SIZE} annotations")
          return
        end

        Annotations::Annotations.new(annotations)
      rescue Validation::DomainValidationError => exc
        errors.add(:annotations, exc.message)
      end

      def init_restricted_to(restricted_to)
        return unless validate_is_class(:base, restricted_to, Array, msg: "restricted_to must be an array")
        return unless validate_restricted_to_size(restricted_to)

        restricted_to.map { |addr| make_valid_cidr_from_addr(addr) }
      end

      def validate_restricted_to_size(restricted_to)
        max_restricted_to = Rails.application.config.conjur_config.max_restricted_to
        if restricted_to.length > max_restricted_to
          errors.add(:base, "Too many CIDR entries. Maximum allowed is #{max_restricted_to}")
          return false
        end
        true
      end

      def make_valid_cidr_from_addr(addr)
        if validate_is_class(:base, addr, String, msg: "Invalid IP address or CIDR range '#{addr}'")
          begin
            Conjur::CIDR.new(addr).to_s
          rescue IPAddr::Error
            errors.add(:base, "Invalid IP address or CIDR range '#{addr}'")
          end
        end
      end
    end
  end
end
