# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      module Validations
        # This class validates the configuration of the Certificate Authenticator
        # as defined by the authenticator's variables.
        #
        # All required and optional variables should be defined here, as well as
        # any validations of their input values.
        class AuthenticatorConfiguration < Authentication::Base::Validations
          schema do
            required(:account).filled(:string)
            required(:service_id).filled(:string)
            required(:ca_cert).filled(:string)

            optional(:crl).value(:string)
            optional(:crl_url).value(:string)
            optional(:host_mode).value(:string)
            optional(:trust_domain).value(:string)
            optional(:identity_path).value(:string)
            optional(:san_uri).value(:string)
            optional(:san_dns).value(:string)
            optional(:san_ip).value(:string)
            optional(:cn).value(:string)
          end
        end
      end
    end
  end
end
