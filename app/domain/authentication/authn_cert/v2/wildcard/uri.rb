# frozen_string_literal:

require 'addressable/uri'

module Authentication
  module AuthnCert
    module V2
      module Wildcard
        # Implement wildcard matching rules for URI Subject Alternate Names.
        #
        # # This module verifies the format of URI patterns and applies them
        # in comparison to fully-formed URIs according to the following rules:
        #
        #   1. Pattern must parse as hierarchical URI (scheme + authority)
        #   2. No wildcards in scheme or authority
        #   3. Path split into segments (trim '/'), each segment either literal (no '*') or exactly '*'
        #   4. '*' matches exactly one non-empty segment
        #   5. Segment counts must be equal
        #   6. Query and fragment ignored
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
        class Uri
          def initialize(logger: Rails.logger)
            @logger = logger
            @messages = LogMessages::Authentication::AuthnCert

            @success = Responses::Success
            @failure = Responses::Failure
          end

          def valid?(pattern)
            return @failure.new(@messages::URIPatternValidationFailed.new(pattern, "pattern may not be empty")) if pattern.nil?

            # Reject illegal double-wildcard.
            if pattern.include?('**')
              return @failure.new(@messages::URIPatternValidationFailed.new(pattern, "double-wildcard not allowed"))
            end

            begin
              uri = Addressable::URI.parse(pattern)
            rescue Addressable::URI::InvalidURIError
              return @failure.new(@messages::URIPatternValidationFailed.new(pattern, "invalid URI format"))
            end

            # Must be hierarchical URI and contain scheme and host
            unless required_components_present?(uri)
              return @failure.new(@messages::URIPatternValidationFailed.new(pattern, "missing scheme or host"))
            end

            # SPIFFE URIs cannot include wildcards
            if uri.scheme.downcase == 'spiffe' && pattern.include?('*')
              return @failure.new(@messages::URIPatternValidationFailed.new(pattern, "wildcards not allowed in SPIFFE URIs"))
            end

            # Wildcards only allowed in path.
            unless pattern.count('*') == uri.path.count('*')
              return @failure.new(@messages::URIPatternValidationFailed.new(pattern, "wildcards only allowed in path"))
            end

            # Validate path segments: wildcard only allowed as entire segment.
            segments = uri.path.split('/')
            if segments.any? { |seg| seg.include?('*') && seg != '*' }
              return @failure.new(@messages::URIPatternValidationFailed.new(pattern, "wildcard must be entire segment"))
            end

            @logger.debug(@messages::URIPatternValidationSucceeded.new)
            @success.new(true)
          end

          def match?(pattern, candidate)
            # Trim trailing slash
            pattern = pattern.delete_suffix('/')
            candidate = candidate.delete_suffix('/')

            # Sanitize whitespace from candidate SAN URI
            candidate = candidate.strip

            begin
              candidate_uri = Addressable::URI.parse(candidate)
              pattern_uri = Addressable::URI.parse(pattern)
            rescue Addressable::URI::InvalidURIError
              return @failure.new(@messages::URIPatternMatchingFailed.new(pattern, candidate, "invalid URI format"))
            end

            # Must be hierarchical URI and contain scheme and host
            unless required_components_present?(pattern_uri) && required_components_present?(candidate_uri)
              return @failure.new(@messages::URIPatternMatchingFailed.new(pattern, candidate, "missing scheme or host"))
            end

            # Must match scheme - case-insensitive
            unless pattern_uri.scheme.downcase == candidate_uri.scheme.downcase
              return @failure.new(@messages::URIPatternMatchingFailed.new(pattern, candidate, "scheme mismatch"))
            end

            # Must match host, userinfo, port - case-sensitive
            unless pattern_uri.host.downcase == candidate_uri.host.downcase
              return @failure.new(@messages::URIPatternMatchingFailed.new(pattern, candidate, "host mismatch"))
            end

            unless pattern_uri.userinfo == candidate_uri.userinfo
              return @failure.new(@messages::URIPatternMatchingFailed.new(pattern, candidate, "userinfo mismatch"))
            end

            unless pattern_uri.port == candidate_uri.port
              return @failure.new(@messages::URIPatternMatchingFailed.new(pattern, candidate, "port mismatch"))
            end

            # Compare path segments
            pattern_segments = pattern_uri.path.split('/')
            candidate_segments = candidate_uri.path.split('/')
            unless path_segment_match?(pattern_segments, candidate_segments)
              return @failure.new(@messages::URIPatternMatchingFailed.new(pattern, candidate, "path segment mismatch"))
            end

            @logger.debug(@messages::URIPatternMatchingSucceeded.new(pattern, candidate))
            @success.new(true)
          end

          private

          def path_segment_match?(pattern_segments, candidate_segments)
            # Must have same number of segments
            return false unless pattern_segments.length == candidate_segments.length

            pattern_segments.zip(candidate_segments).all? do |pattern_segment, candidate_segment|
              if pattern_segment == '*'
                candidate_segment.present?
              else
                pattern_segment == candidate_segment
              end
            end
          end

          def required_components_present?(uri)
            return false unless uri.scheme.present?
            return false unless uri.host.present?

            true
          end
        end
      end
    end
  end
end
