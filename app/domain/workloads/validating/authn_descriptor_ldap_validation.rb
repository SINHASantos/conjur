# frozen_string_literal: true

module Workloads
  module Validating
    module AuthnDescriptorLdapValidation
      include Validation

      def validate_ldap_vars
        if @data[:bind_password]
          validate_is_class(:data, @data[:bind_password], String, attr_name: :bind_password)
        end
        if @data[:tls_ca_cert]
          validate_is_class(:data, @data[:tls_ca_cert], String, attr_name: :tls_ca_cert)
        end

        return unless @data[:bind_password].nil? && !@data[:tls_ca_cert].nil?
        # Using tls-ca-cert implies we are using the variable/annotation config for this authenticator
        # which implies we require the bind-password be set
        raise(
          Errors::Conjur::ParameterMissing,
          "The 'bind_password' field must be specified when the 'tls_ca_cert' field is provided."
        )
      end
    end
  end
end
