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
        #
        # This class is used to validate wildcard patterns in certificate
        # authenticator configuration both:
        #
        #   1. At authentication time, to catch misconfiguration created by
        #      policy and variable value loads, and...
        #   2. At authenticator creation/update time, performed via the V2
        #      Authenticators CRUD API.
        #
        # These operations have different requirements regarding error visibility.
        # Authentication obscures detailed error messages from the authenticating
        # role for security purposes, while the V2 API surfaces more detailed
        # error responses for a better user experience. The methods that this
        # class implements will return `Success` and `Failure` response objects
        # that contain detailed messages - they should be logged, and not returned,
        # in authentication flows.
        class IpAddress
          def initialize(logger: Rails.logger)
            @logger = logger
            @messages = LogMessages::Authentication::AuthnCert

            @success = Responses::Success
            @failure = Responses::Failure
          end

          def valid?(pattern)
            return @failure.new(@messages::IPPatternValidationFailed.new(pattern, "pattern may not be empty")) if pattern.blank?

            # Reject wildcards in IP addresses.
            if pattern.include?('*')
              return @failure.new(@messages::IPPatternValidationFailed.new(pattern, "wildcards not allowed"))
            end

            # Reject IP addresses in CIDR notation, as this would require
            # matching a range of IP addresses to the pattern based on the
            # subnet mask.
            if pattern.include?('/')
              return @failure.new(@messages::IPPatternValidationFailed.new(pattern, "CIDR notation not allowed"))
            end

            # Confirm that the pattern is in fact a valid IP address. Invalid
            # IPs will raise an exception and be caught below.
            IPAddr.new(pattern)

            @logger.debug(@messages::IPPatternValidationSucceeded.new(pattern))
            @success.new(true)
          rescue
            @failure.new(@messages::IPPatternValidationFailed.new(pattern, "invalid IP address"))
          end

          def match?(pattern, candidate)
            unless pattern == candidate
              return @failure.new(@messages::IPPatternMatchingFailed.new(pattern, candidate))
            end

            @logger.debug(@messages::IPPatternMatchingSucceeded.new(pattern, candidate))
            @success.new(true)
          end
        end
      end
    end
  end
end
