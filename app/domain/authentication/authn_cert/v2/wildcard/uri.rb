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
            return false if pattern.include?('**')

            begin
              uri = Addressable::URI.parse(pattern)
            rescue Addressable::URI::InvalidURIError
              return false
            end

            # Must be hierarchical URI and contain scheme and host
            return false unless required_components_present?(uri)

            # SPIFFE URIs cannot include wildcards
            return false if uri.scheme.downcase == 'spiffe' && pattern.include?('*')

            # Wildcards only allowed in path.
            return false unless pattern.count('*') == uri.path.count('*')

            # Validate path segments: wildcard only allowed as entire segment.
            segments = uri.path.split('/')
            return false if segments.any? { |seg| seg.include?('*') && seg != '*' }

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
              return false
            end

            # Must be hierarchical URI and contain scheme and host
            return false unless required_components_present?(pattern_uri)
            return false unless required_components_present?(candidate_uri)

            # Must match scheme - case-insensitive
            return false unless pattern_uri.scheme.downcase == candidate_uri.scheme.downcase

            # Must match host, userinfo, port - case-sensitive
            return false unless pattern_uri.host.downcase == candidate_uri.host.downcase
            return false unless pattern_uri.userinfo == candidate_uri.userinfo
            return false unless pattern_uri.port == candidate_uri.port

            # Compare path segments
            pattern_segments = pattern_uri.path.split('/')
            candidate_segments = candidate_uri.path.split('/')
            return false unless path_segment_match?(pattern_segments, candidate_segments)

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
