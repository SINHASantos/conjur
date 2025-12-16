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
            return false if pattern.include?('*')

            # Reject IP addresses in CIDR notation, as this would require
            # matching a range of IP addresses to the pattern based on the
            # subnet mask.
            return false if pattern.include?('/')

            # Confirm that the pattern is in fact a valid IP address. Invalid
            # IPs will raise an exception and be caught below.
            IPAddr.new(pattern)
            true
          rescue
            false
          end

          def self.match?(pattern, candidate)
            pattern == candidate
          end
        end
      end
    end
  end
end