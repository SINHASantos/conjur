# frozen_string_literal: true

module AuthenticatorsV2
  class CertAuthenticatorType < AuthenticatorBaseType
    def data
      return {} if @variables.blank?

      identity = identity_fields
      {
        ca_cert: format_field(@variables[:ca_cert]),
        crl: format_field(@variables[:crl]),
        crl_url: format_field(@variables[:crl_url]),
        identity: identity.present? ? identity : nil
      }.compact
    end

    def identity_path
      @variables[:identity_path]
    end

    def format_type
      "certificate"
    end

    private

    def identity_fields
      {
        host_mode: format_field(@variables[:host_mode]),
        trust_domain: format_field(@variables[:trust_domain]),
        identity_path: format_field(@variables[:identity_path]),
        san_uri: @variables[:san_uri].nil? ? nil : san_list(@variables[:san_uri]),
        san_dns: @variables[:san_dns].nil? ? nil : san_list(@variables[:san_dns]),
        san_ip: @variables[:san_ip].nil? ? nil : san_list(@variables[:san_ip]),
        cn: format_field(@variables[:cn])
      }.compact
    end

    def san_list(value)
      return [] if value.strip.empty?

      value.split(',', -1).reject{ |san| san == '' }.map(&:strip).uniq
    end
  end
end
