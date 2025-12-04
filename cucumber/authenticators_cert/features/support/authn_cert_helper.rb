# frozen_string_literal: true

require 'cgi'

module AuthnCertHelper
  ACCOUNT = 'cucumber'

  def authenticate_with_certificate(service_id:, account:, client_cert:, client_key:, user_id:)
    path = "#{conjur_hostname}/authn-cert/#{service_id}/#{account}/#{user_id}/authenticate"

    post(path, '', {
      "X-SSL-Client-Certificate": CGI.escape(client_cert.to_pem)
    })
  end

  def generate_ca_certificate(common_name:)
    key = OpenSSL::PKey::RSA.new(2048)
    name = OpenSSL::X509::Name.parse(common_name)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = name
    cert.issuer = name
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 365 * 24 * 60 * 60

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(ef.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    cert.add_extension(ef.create_extension('extendedKeyUsage', 'serverAuth,clientAuth', false))

    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end

  def generate_client_certificate(ca_cert:, ca_key:, common_name:)
    key = OpenSSL::PKey::RSA.new(2048)
    name = OpenSSL::X509::Name.parse(common_name)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = name
    cert.issuer = ca_cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 365 * 24 * 60 * 60

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = ca_cert
    cert.add_extension(ef.create_extension('basicConstraints', 'CA:FALSE', true))
    cert.add_extension(ef.create_extension('keyUsage', 'digitalSignature', true))
    cert.add_extension(ef.create_extension('extendedKeyUsage', 'serverAuth,clientAuth', false))

    cert.sign(ca_key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end
end

World(AuthnCertHelper)
