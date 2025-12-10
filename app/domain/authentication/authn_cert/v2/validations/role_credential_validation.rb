# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      module Validations
        # This class validates that a client's X.509 certificate aligns with the
        # resource restriction set as annotations on the target role. In the
        # context of AuthnCert, we confirm that Subject Alternate Names
        # specified via annotations are present in the client's certificate.
        #
        # Due to the data flow of the authenticators architecture, this class
        # operates on the following assumptions:
        #   1. That annotation-based restrictions have been validated for
        #      presence, count, and validity by the AuthenticatorRoleRepository
        #      using the Validations::Constraints class.
        #   2. Given 1, the provided annotation set being empty is a valid state.
        #   3. That the credential has been successfully validated, and
        #      therefore the map of credential attributes cannot realistically
        #      be nil or empty.
        class RoleCredentialValidation
          include ActiveModel::Validations

          attr_reader :authenticator, :credential_attributes

          validates :authenticator, presence: true
          validates :credential_attributes, presence: true

          # Given assumption #2, the validations below should only be performed
          # if the annotations set is non-empty.
          validate :annotations_have_values, if: -> { annotations_present_and_valid? }
          validate :annotation_values_valid, if: -> { annotations_present_and_valid? }
          validate :annotations_match_credential, if: -> { annotations_present_and_valid? }

          def initialize(annotations:, authenticator:, credential_attributes:, logger: Rails.logger)
            @annotations = annotations
            @authenticator = authenticator
            @credential_attributes = credential_attributes
            @logger = logger

            @dns_matcher = Authentication::AuthnCert::V2::Wildcard::DnsName
            @uri_matcher = Authentication::AuthnCert::V2::Wildcard::Uri
            @base_matcher = Authentication::AuthnCert::V2::Wildcard::Base
          end

          private

          def annotations_present_and_valid?
            @annotations.any? && errors.empty?
          end

          def annotations_have_values
            @annotations.each do |annotation, value|
              if value.blank?
                errors.add(:base, Errors::Authentication::ResourceRestrictions::EmptyAnnotationGiven.new(annotation))
              end
            end
          end

          def annotation_values_valid
            @annotations.each do |annotation, value|
              validate_value(annotation, value, matcher_for(annotation))
            end
          end

          def annotations_match_credential
            @annotations.each do |annotation, value|
              compare_value_to_credential(annotation, value, attribute_for(annotation), matcher_for(annotation))
            end
          end

          def validate_value(annotation, patterns_s, matcher)
            patterns = patterns_s.split(',').map(&:strip)
            invalid_patterns = patterns.reject { |pattern| matcher.valid?(pattern)}
            return if invalid_patterns.empty?

            errors.add(:base, Errors::Authentication::Certificate::InvalidWildcards.new(annotation, invalid_patterns))
          end

          def compare_value_to_credential(annotation, patterns_s, names, matcher)
            patterns = patterns_s.split(',').map(&:strip)
            patterns.each do |pattern|
              next if pattern_matches_any_name?(pattern, names, matcher)

              errors.add(:base, Errors::Authentication::ResourceRestrictions::InvalidResourceRestrictions.new(annotation))
              break
            end
          end

          def pattern_matches_any_name?(pattern, names, matcher)
            return false if names.nil? || names.empty?

            names.any? { |name| matcher.match?(pattern, name) }
          end

          def matcher_for(annotation)
            case annotation
            when 'san-dns'
              @dns_matcher
            when 'san-uri'
              @uri_matcher
            when 'san-ip', 'cn'
              @base_matcher
            else
              # This case should never be reached according to assumption #1.
              @base_matcher
            end
          end

          def attribute_for(annotation)
            case annotation
            when 'san-dns'
              @credential_attributes['san_dns']
            when 'san-uri'
              @credential_attributes['san_uri']
            when 'san-ip'
              @credential_attributes['san_ip']
            when 'cn'
              [@credential_attributes['common_name']]
            else
              # This case should never be reached according to assumption #1.
              []
            end
          end
        end
      end
    end
  end
end
