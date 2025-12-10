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
            rescue URI::InvalidURIError
              return false
            end

            # SPIFFE URIs cannot include wildcards
            return false if uri.scheme&.downcase == 'spiffe' && pattern.include?('*')

            # Wildcard not allowed in host or userinfo.
            return false if uri.host.to_s.include?('*')
            return false if uri.userinfo.to_s.include?('*')

            # Validate path segments: wildcard only allowed as entire segment.
            path = uri.path.to_s
            segments = path.split('/').reject(&:empty?)
            return false if segments.any? { |seg| seg.include?('*') && seg != '*' }

            true
          end

          def self.match?(pattern, candidate)
            # Trim at most 1 leading/trailing slash
            pattern = pattern.delete_prefix('/').delete_suffix('/')
            candidate = candidate.delete_prefix('/').delete_suffix('/')

            # Sanitize whitespace from candidate SAN URI
            candidate = candidate.strip

            begin
              candidate_uri = Addressable::URI.parse(candidate)
              pattern_uri = Addressable::URI.parse(pattern)
            rescue Addressable::URI::InvalidURIError => e
              return false
            end

            # Must be hierarchical URI and contain scheme and host
            return false unless candidate_uri.scheme && candidate_uri.host
            # Must match scheme - case-insensitive
            return false unless pattern_uri.scheme && candidate_uri.scheme.downcase == pattern_uri.scheme.downcase
            # Must match userinfo
            return false unless candidate_uri.userinfo == pattern_uri.userinfo
            # Must match host
            return false unless candidate_uri.host && !candidate_uri.host.empty? && pattern_uri.host && !pattern_uri.host.empty? && candidate_uri.host == pattern_uri.host
            # Must match port
            return false unless candidate_uri.port == pattern_uri.port

            puts "Pattern Path: #{pattern_uri.path}, Candidate Path: #{candidate_uri.path}"

            # Compare path segments
            pattern_segments = raw_path(pattern, pattern_uri.host).split('/')
            candidate_segments = raw_path(candidate, candidate_uri.host).split('/')
            return false unless path_segment_match?(pattern_segments, candidate_segments)
            true
          end

          def self.path_segment_match?(pattern_segments, candidate_segments)
            # Must have same number of segments
            return false unless pattern_segments.length == candidate_segments.length

            pattern_segments.zip(candidate_segments).all? do |pattern_segment, candidate_segment|
              if pattern_segment == '*'
                candidate_segment && !candidate_segment.empty?
              else
                pattern_segment == candidate_segment
              end
            end
          end

          def self.raw_path(uri_str, host)
            host_index = uri_str.index(host)
            return  URI::InvalidURIError unless host_index

            # Find the first slash after the host
            slash_index = uri_str.index('/', host_index + host.length)
            path = slash_index ? uri_str[slash_index..-1] : ''

            # Remove query parameters and fragment if present
            path_end = [path.index('?'), path.index('#')].compact.min
            path = path_end ? path[0...path_end] : path

            # Default to root if path is empty
            path = '/' if path.empty?
            path
          end

        end
      end
    end
  end
end
