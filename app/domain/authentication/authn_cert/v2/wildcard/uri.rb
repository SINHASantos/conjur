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
        class Uri
          def self.valid?(pattern)
            return false if pattern.nil?

            # Reject illegal double-wildcard.
            if pattern.include?('**')
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternValidationDoubleWildcard.new)
              return false
            end

            begin
              uri = Addressable::URI.parse(pattern)
            rescue Addressable::URI::InvalidURIError
              Rails.logger.error(LogMessages::Authentication::AuthnCert::URIParseError)
              return false
            end

            # Must be hierarchical URI and contain scheme and host
            unless required_components_present?(uri)
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternValidationMissingSchemeOrHost.new)
              return false
            end

            # SPIFFE URIs cannot include wildcards
            if uri.scheme.downcase == 'spiffe' && pattern.include?('*')
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternValidationWildcardNotAllowedInSPIFFE.new)
              return false
            end

            # Wildcards only allowed in path.
            unless pattern.count('*') == uri.path.count('*')
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternValidationWildcardOnlyInPath.new)
              return false
            end

            # Validate path segments: wildcard only allowed as entire segment.
            segments = uri.path.split('/')
            if segments.any? { |seg| seg.include?('*') && seg != '*' }
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternValidationWildcardEntireSegment.new)
              return false
            end

            Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternValidationSucceeded.new)
            true
          end

          def self.match?(pattern, candidate)
            # Trim trailing slash
            pattern = pattern.delete_suffix('/')
            candidate = candidate.delete_suffix('/')

            # Sanitize whitespace from candidate SAN URI
            candidate = candidate.strip

            begin
              candidate_uri = Addressable::URI.parse(candidate)
              pattern_uri = Addressable::URI.parse(pattern)
            rescue Addressable::URI::InvalidURIError
              Rails.logger.error(LogMessages::Authentication::AuthnCert::URIParseError)
              return false
            end

            # Must be hierarchical URI and contain scheme and host
            unless required_components_present?(pattern_uri) && required_components_present?(candidate_uri)
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternMatchingMissingSchemeOrHost.new)
              return false
            end

            # Must match scheme - case-insensitive
            unless pattern_uri.scheme.downcase == candidate_uri.scheme.downcase
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternMatchingSchemeMismatch.new)
              return false
            end

            # Must match host, userinfo, port - case-sensitive
            unless pattern_uri.host.downcase == candidate_uri.host.downcase
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternMatchingHostMismatch.new)
              return false
            end

            unless pattern_uri.userinfo == candidate_uri.userinfo
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternMatchingUserinfoMismatch.new)
              return false
            end

            unless pattern_uri.port == candidate_uri.port
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternMatchingPortMismatch.new)
              return false
            end

            # Compare path segments
            pattern_segments = pattern_uri.path.split('/')
            candidate_segments = candidate_uri.path.split('/')
            unless path_segment_match?(pattern_segments, candidate_segments)
              Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternMatchingPathSegmentMismatch.new)
              return false
            end

            Rails.logger.debug(LogMessages::Authentication::AuthnCert::URIPatternMatchingSucceeded.new)
            true
          end

          def self.path_segment_match?(pattern_segments, candidate_segments)
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

          def self.required_components_present?(uri)
            return false unless uri.scheme.present?
            return false unless uri.host.present?

            true
          end
        end
      end
    end
  end
end
