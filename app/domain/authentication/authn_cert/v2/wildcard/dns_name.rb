# frozen_string_literal

require 'public_suffix'

module Authentication
  module AuthnCert
    module V2
      module Wildcard
        # Implement wildcard matching rules for DNS Name Subject Alternate Names.
        #
        # DNS names are constructed of labels, including a top-level domain
        # (TLD) and a series of subdomains. The first subdomain is called a
        # second-level domain (SLD).
        #
        # An effective top-level domain (eTLD) is a domain under which domains
        # can be registered by a single organization, and sometimes extends past
        # the top-level. The list of eTLDs is found here: https://publicsuffix.org/
        #
        # eTLD+1 includes the next label alongside the eTLD. All names that
        # share an eTLD+1 are owned by the same organization.
        #
        #   DNS Name: secretsmanager.cyberark.ma.us
        #   TLD     :                            us
        #   eTLD    :                         ma.us
        #   eTLD+1  :                cyberark.ma.us
        #
        # This module verifies the format of DNS Name patterns and applies them
        # in comparison to fully-formed DNS Names according to the following rules:
        #
        #   1. Wildcards may not be included in the eTLD+1.
        #   2. Wildcards may replace an entire label or the beginning of a label.
        #   3. Wildcards may not cross label boundaries.
        #   4. Subdomain labels may include only a single wildcard.
        #   5. Wildcards may appear in or replace multiple subdomain labels.
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
        class DnsName
          def initialize(logger: Rails.logger)
            @logger = logger
            @messages = LogMessages::Authentication::AuthnCert

            @success = Responses::Success
            @failure = Responses::Failure
          end

          def valid?(pattern)
            pattern = pattern.downcase

            # Reject illegal double-wildcard.
            if pattern.include?('**')
              return @failure.new(@messages::DNSPatternValidationFailed.new(pattern, "double-wildcard not allowed"))
            end

            # Reject domain names with empty labels.
            if pattern.include?('..') || pattern.start_with?('.') || pattern.end_with?('.')
              return @failure.new(@messages::DNSPatternValidationFailed.new(pattern, "empty labels are not allowed"))
            end

            # Parse the pattern into a PublicSuffix::Domain instance.
            parsed_pattern = PublicSuffix.parse(pattern)

            # PublicSuffix::Domain#domain returns the string representation of
            # the eTLD+1.
            etld1 = parsed_pattern.domain

            # Reject domain names with wildcard in eTLD+1.
            if etld1.include?('*')
              return @failure.new(@messages::DNSPatternValidationFailed.new(pattern, "wildcard in eTLD+1 not allowed"))
            end

            # PublicSuffix::Domain#to_a always returns an array of length 3.
            #   [ remainder, +1, eTLD ]
            # For example:
            #   "google.co.uk"    => [    nil, "google", "co.uk" ]
            #   "mail.google.com" => [ "mail", "google",   "com" ]
            leading_remainder = parsed_pattern.to_a[0]
            unless leading_remainder.nil?
              # Validate DNS name segments outside the eTLD+1.
              leading_remainder.split('.').each do |segment|
                if segment.blank? || !valid_segment?(segment)
                  return @failure.new(@messages::DNSPatternValidationFailed.new(pattern, "invalid segment '#{segment}'"))
                end
              end
            end

            @logger.debug(@messages::DNSPatternValidationSucceeded.new(pattern))
            @success.new(true)
          rescue PublicSuffix::DomainInvalid, PublicSuffix::DomainNotAllowed
            @failure.new(@messages::DNSPatternValidationFailed.new(pattern, "invalid DNS name"))
          end

          def match?(pattern, dns_name)
            # Sanitize whitespace from candidate DNS name.
            dns_name = dns_name.strip.downcase

            # If the pattern does not contain a wildcard, we can do a direct
            # string comparison.
            unless pattern.include?('*')
              return @success.new(true) if dns_name == pattern

              return @failure.new(@messages::DNSPatternMatchingFailed.new(pattern, dns_name, "direct comparison failed"))
            end

            pattern_segments = pattern.split('.')
            candidate_segments = dns_name.split('.')
            if candidate_segments.length != pattern_segments.length
              return @failure.new(@messages::DNSPatternMatchingFailed.new(pattern, dns_name, "segment count mismatch"))
            end

            pattern_segments.zip(candidate_segments).each do |pattern_label, candidate_label|
              # Empty labels in the candidate DNS name should be rejected.
              if candidate_label.blank?
                return @failure.new(@messages::DNSPatternMatchingFailed.new(pattern, dns_name, "empty label in candidate DNS name"))
              end

              # Wildcards that make up an entire label in the pattern DNS name
              # match the entire label in the candidate DNS name by default.
              next if pattern_label == '*'

              # Labels in the pattern DNS name with a leading wildcard need to
              # match the rest of the label content against the candidate label.
              if pattern_label.start_with?('*')
                suffix = pattern_label[1..-1]
                next if candidate_label.end_with?(suffix)
              end

              # Compare labels without wildcards directly.
              if pattern_label != candidate_label
                return @failure.new(@messages::DNSPatternMatchingFailed.new(pattern, dns_name, "label mismatch"))
              end
            end

            @logger.debug(@messages::DNSPatternMatchingSucceeded.new(pattern, dns_name))
            @success.new(true)
          end

          private

          def valid_segment?(segment)
            # Allow segments that consist of a single wildcard that represents
            # the entire label.
            return true if segment == '*'

            # Reject segments that include more than a single wildcard.
            return false if segment.count('*') > 1

            # Allow segments that start with a wildcard, but ends with
            # additional, strictly matching text.
            return true if segment.start_with?('*')

            # Reject segments that include a single wildcard anywhere but the
            # very beginning of the string.
            !segment.include?('*')
          end
        end
      end
    end
  end
end
