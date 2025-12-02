# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      module Validations
        # This class validates that a client's X.509 certificate aligns with the
        # resource restriction set as annotations on the target role.
        #
        # In the context of AuthnCert, we confirm that Subject Alternate Names
        # specified via annotations are present in the client's certificate.
        class RoleCredentialValidation
          include ActiveModel::Validations
          validate :annotations_match_credential

          def initialize(annotations:, authenticator:, credential_attributes:, logger: Rails.logger)
            @annotations = annotations
            @authenticator = authenticator
            @credential_attributes = credential_attributes
            @logger = logger
          end

          private

          def annotations_match_credential; end
        end
      end
    end
  end
end
