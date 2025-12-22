# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      module Wildcard
        # Wildcards can be present in either host-specific annotations, or in
        # webservice-specific authenticator configuration variables. This class
        # implements methods to validate and enforce wildcard patterns in both
        # contexts.
        #
        # Due to the data flow of the authenticators architecture, this class
        # operates on the assumption that:
        #   1. Annotation-based restrictions have been validated for presence,
        #      count, and validity by the AuthenticatorRoleRepository using the
        #      Validations::Constraints class.
        #   2. Variable-based restrictions are handled more statically, and the
        #      class that invokes this enforcer is responsible for only working
        #      with applicable variables.
        class Enforcer
          def self.value_valid?(patterns_s, matcher)
            patterns = patterns_s.split(',').map(&:strip)
            patterns.each do |pattern|
              response = matcher.valid?(pattern)

              next if response.success?

              Rails.logger.debug(response.to_s)
              return false
            end
          end

          def self.value_matches_credential?(patterns_s, names, matcher)
            patterns = patterns_s.split(',').map(&:strip)
            patterns.all? { |pattern| pattern_matches_any_name?(pattern, names, matcher) }
          end

          def self.pattern_matches_any_name?(pattern, names, matcher)
            return false if names.nil? || names.empty?

            names.each do |name|
              response = matcher.match?(pattern, name)
              return true if response.success?

              Rails.logger.debug(response.to_s)
            end

            false
          end

          def self.matcher_for(annotation)
            case annotation
            when 'san-dns', 'cn'
              Authentication::AuthnCert::V2::Wildcard::DnsName.new
            when 'san-uri'
              Authentication::AuthnCert::V2::Wildcard::Uri.new
            when 'san-ip'
              Authentication::AuthnCert::V2::Wildcard::IpAddress.new
            else
              # This case should never be reached according to assumptions #1 and 2.
              nil
            end
          end

          def self.attribute_for(annotation, credential_attributes)
            case annotation
            when 'san-dns'
              credential_attributes['sans_dns']
            when 'san-uri'
              credential_attributes['sans_uri']
            when 'san-ip'
              credential_attributes['sans_ip']
            when 'cn'
              [credential_attributes['common_name']]
            else
              # This case should never be reached according to assumption #1 and 2.
              []
            end
          end
        end
      end
    end
  end
end
