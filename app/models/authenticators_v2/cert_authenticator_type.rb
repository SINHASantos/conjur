# frozen_string_literal: true

module AuthenticatorsV2
  class CertAuthenticatorType < AuthenticatorBaseType
    MAX_CA_CERT_SIZE = 100 * 1024 # 100 KB
    MAX_CRL_SIZE = 512 * 1024 # 512 KB
    MAX_CRL_URL_LENGTH = 1024 # 1024 characters
    CRL_URL_PATTERN = %r{\Ahttps?://[^?]+\z} # URL starts with http:// or https:// and does not include a question mark
    CA_CERT_PATTERN = %r{-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\n]+\s*-----END CERTIFICATE-----}
    CRL_PATTERN = %r{-----BEGIN X509 CRL-----\s*[A-Za-z0-9+/=\n]+\s*-----END X509 CRL-----}
    MAX_SAN_URI_ENTRY_COUNT = 10
    MAX_SAN_URI_ENTRY_LENGTH = 512
    MAX_SAN_DNS_ENTRY_COUNT = 10
    MAX_SAN_DNS_ENTRY_LENGTH = 255
    MAX_CN_LENGTH = 64
    MAX_SAN_IP_ENTRY_COUNT = 10
    LIST_SEPARATOR = ','

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

      value.split(LIST_SEPARATOR, -1).reject{ |san| san == '' }.map(&:strip).uniq
    end
  end
end
