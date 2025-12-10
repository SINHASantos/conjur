# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      module Wildcard
        # Implement the matcher interface, but for those values that are not
        # subject to unique wildcard rules.
        class Base
          def self.valid?(pattern)
            pattern.is_a?(String)
          end

          def self.match?(pattern, value)
            pattern == value
          end
        end
      end
    end
  end
end
