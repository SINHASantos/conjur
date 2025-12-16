# frozen_string_literal: true

require 'ipaddr'

module Authentication
  module AuthnCert
    module V2
      module Wildcard
        # Implement wildcard matching rules for IP Address Subject Alternate
        # Names...except we don't support wildcards in IP addresses!
        #
        # We'll use this class to check that the IP Address "patterns" are valid
        # IP addresses, and then perform simple string comparisons against
        # client certificate attributes.
        class IpAddress
          def self.valid?(pattern)
            return false if pattern.empty?

            # Reject wildcards in IP addresses.
            if pattern.include?('*')
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::IPPatternValidationWildcardsNotAllowed.new)
              return false
            end

            # Reject IP addresses in CIDR notation, as this would require
            # matching a range of IP addresses to the pattern based on the
            # subnet mask.
            if pattern.include?('/')
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::IPPatternValidationCIDRNotAllowed.new)
              return false
            end

            # Confirm that the pattern is in fact a valid IP address. Invalid
            # IPs will raise an exception and be caught below.
            IPAddr.new(pattern)

            Rails.logger.debug(LogMessages::Authentication::AuthnCert::IPPatternValidationSucceeded.new)
            true
          rescue
            Rails.logger.error(LogMessages::Authentication::AuthnCert::IPPatternValidationInvalidIPError.new)
            false
          end

          def self.match?(pattern, candidate)
            result = pattern == candidate
            if result
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::IPPatternMatchingSucceeded.new)
            else
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::IPPatternMatchingFailed.new)
            end
            result
          end
        end
      end
    end
  end
end
