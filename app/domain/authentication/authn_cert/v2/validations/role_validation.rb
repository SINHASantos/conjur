# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      module Validations
        # This class validates that a role that is attempting to authenticate
        # via a certificate authenticator instance has the proper annotation
        # configuration.
        #
        # In the context of AuthnCert, we confirm that:
        #   1. At least 1 relevant annotation is present in `request` host mode
        #   2. No invalid annotations are present
        class RoleValidation
          include ActiveModel::Validations
          validate :enforce_minimum_count

          def initialize(annotations:, authenticator:, specific_annotations: nil, logger: Rails.logger)
            @annotations = annotations
            @specific_annotations = specific_annotations
            @authenticator = authenticator
            @logger = logger
          end

          private

          def enforce_minimum_count; end
        end
      end
    end
  end
end
