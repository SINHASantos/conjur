# frozen_string_literal: true

require 'public_suffix'

module Authentication
  module AuthnCert
    module V2
      module Wildcard
        # Implement wildcard matching rules for Common Names.
        #
        # Common Names are often DNS names, but may also be simple strings. In
        # the case where a Common Name is a valid DNS name, the DNS Name
        # wildcard rules apply. Otherwise, we perform simple string comparison.
        class CommonName
          def initialize(logger: Rails.logger)
            @logger = logger
            @dns_matcher = DnsName

            @success = Responses::Success
            @failure = Responses::Failure
          end

          def valid?(pattern)
            response = if PublicSuffix.valid?(pattern)
              enforce_dns_pattern_validation_rules(pattern)
            else
              enforce_standard_pattern_validation_rules(pattern)
            end

            if response.success?
              @logger.debug(LogMessages::Authentication::AuthnCert::CommonNamePatternValidationSucceeded.new(pattern))
            end
            response
          end

          def match?(pattern, common_name)
            response = if PublicSuffix.valid?(pattern)
              enforce_dns_pattern_matching_rules(pattern, common_name)
            else
              enforce_standard_pattern_matching_rules(pattern, common_name)
            end

            if response.success?
              @logger.debug(LogMessages::Authentication::AuthnCert::CommonNamePatternMatchingSucceeded.new(pattern, common_name))
            end
            response
          end

          private

          def enforce_dns_pattern_validation_rules(pattern)
            response = @dns_matcher.new(logger: @logger).valid?(pattern)
            return response if response.success?

            @failure.new(
              LogMessages::Authentication::AuthnCert::CommonNamePatternValidationFailed.new(pattern, response.message)
            )
          end

          def enforce_standard_pattern_validation_rules(pattern)
            return @success.new(true) unless pattern.blank?

            @failure.new(
              LogMessages::Authentication::AuthnCert::CommonNamePatternValidationFailed.new(pattern, "pattern may not be empty")
            )
          end

          def enforce_dns_pattern_matching_rules(pattern, common_name)
            response = @dns_matcher.new(logger: @logger).match?(pattern, common_name)
            return response if response.success?

            @failure.new(
              LogMessages::Authentication::AuthnCert::CommonNamePatternMatchingFailed.new(pattern, common_name)
            )
          end

          def enforce_standard_pattern_matching_rules(pattern, common_name)
            return @success.new(true) if pattern == common_name

            @failure.new(
              LogMessages::Authentication::AuthnCert::CommonNamePatternMatchingFailed.new(pattern, common_name)
            )
          end
        end
      end
    end
  end
end
