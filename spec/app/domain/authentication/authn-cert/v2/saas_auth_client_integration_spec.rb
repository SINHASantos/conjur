# frozen_string_literal: true

require 'spec_helper'
require 'webrick'
require 'webrick/https'
require 'openssl'
require 'webmock/rspec'
require 'tempfile'
require 'net/http'

HTTP_URL = "http://localhost"
HTTPS_URL = "https://localhost"
AUTH_PATH = '/authentications/cert'
RESPONSE_BODY = { attributes: { attr: 'value' } }.to_json
HTTP_UNREACHABLE_URL = 'http://unreachable-host:2222'

RSpec.describe(Authentication::AuthnCert::V2::SaasAuthClient) do
  let(:authenticator) do
    AuthenticatorsV2::CertAuthenticatorType.new(
      account: 'rspec',
      service_id: 'my-service',
      variables: {}
    )
  end

  # Create an http server on a random port that responds with a fixed response
  def start_http_server()
    server = WEBrick::HTTPServer.new(
      Port: 0,
      Logger: WEBrick::Log.new('/dev/null'),
      AccessLog: []
    )
    server.mount_proc(AUTH_PATH) do |_, res|
      res.status = 200
      res['Content-Type'] = 'application/json'
      res.body = RESPONSE_BODY
    end
    thread = Thread.new { server.start }
    [server, thread]
  end

  # Create an https server on a random port that responds with a fixed response
  def start_https_server(cert:, key:)
    server = WEBrick::HTTPServer.new(
      Port: 0,
      SSLEnable: true,
      SSLCertificate: cert,
      SSLPrivateKey: key,
      Logger: WEBrick::Log.new('/dev/null'),
      AccessLog: []
    )
    server.mount_proc(AUTH_PATH) do |_, res|
      res.status = 200
      res['Content-Type'] = 'application/json'
      res.body = RESPONSE_BODY
    end
    thread = Thread.new { server.start }
    [server, thread]
  end

  def generate_cert(subject: 'CN=Test CA', filename: 'ca_cert')
    key = OpenSSL::PKey::RSA.new(2048)
    cert = Util::OpenSsl::X509::Certificate.from_subject(
      subject: subject,
      key: key,
      extensions: [
        ['basicConstraints', 'CA:TRUE', true],
        ['extendedKeyUsage', 'serverAuth', false],
        ['subjectAltName', 'DNS:localhost', false]
      ]
    )
    ca_cert_file = Tempfile.new(filename)
    ca_cert_file.write(cert.to_pem)
    ca_cert_file.close
    [cert, key, ca_cert_file]
  end

  def wait_for_server(url, timeout: 5, interval: 0.05, ca_cert_path: nil)
    uri = URI(url)
    Timeout.timeout(timeout) do
      loop do
        begin
          Net::HTTP.start(
            uri.host,
            uri.port,
            use_ssl: uri.scheme == "https",
            open_timeout: 1,
            read_timeout: 1
          ) do |http|
            if uri.scheme == "https" && ca_cert_path
              http.ca_file = ca_cert_path
              http.verify_mode = OpenSSL::SSL::VERIFY_PEER
            end
            http.get(uri.path)
          end
          break
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError
          sleep(interval)
        end
      end
    end
  end

  before(:all) do
    VCR.turned_off do
      @http_server, @http_thread = start_http_server
      http_port = @http_server.config[:Port]
      @http_url = "#{HTTP_URL}:#{http_port}"

      cert, key, @ca_cert_file = generate_cert
      @https_server, @https_thread = start_https_server(cert: cert, key: key)
      https_port = @https_server.config[:Port]
      @https_url = "#{HTTPS_URL}:#{https_port}"

      _, _, @incorrect_ca_cert_file = generate_cert(subject:"CN=Incorrect CA", filename: 'incorrect_ca_cert')

      WebMock.disable_net_connect!(allow: [@http_url, @https_url, HTTP_UNREACHABLE_URL])

      wait_for_server("#{@http_url}#{AUTH_PATH}")
      wait_for_server("#{@https_url}#{AUTH_PATH}", ca_cert_path: @ca_cert_file.path)
    end
  end

  after(:all) do
    @http_server.shutdown
    @http_thread.kill
    @https_server.shutdown
    @https_thread.kill
    WebMock.disable_net_connect!

    @ca_cert_file&.unlink
    @incorrect_ca_cert_file&.unlink
  end

  let(:transporter_class) { Authentication::Util::NetworkTransporter }

  describe '#validate_certificate' do
    context 'when using HTTP' do
      context 'with allowed host' do
        it 'connects successfully' do
          client = described_class.new(
            http_client: transporter_class,
            authenticator_service_url: @http_url,
            ca_cert_path: nil,
            http_allowlist: ['localhost']
          )
          response = client.validate_certificate(certificate: 'dummy', authenticator: authenticator)
          expect(response.success?).to be(true)
          expect(response.result['attributes']['attr']).to eq('value')
        end
      end

      context 'with disallowed host' do
        it 'raises HttpNotAllowed error' do
          expect {
            described_class.new(
              http_client: transporter_class,
              authenticator_service_url: @http_url,
              ca_cert_path: nil,
              http_allowlist: ['127.0.0.1']
            )
          }.to raise_error(Errors::Authentication::Security::HttpNotAllowed)
        end
      end

      context 'with unreachable host' do
        it 'returns failure response' do
          client = described_class.new(
            http_client: transporter_class,
            authenticator_service_url: HTTP_UNREACHABLE_URL,
            ca_cert_path: nil,
            http_allowlist: ['unreachable-host']
          )
          response = client.validate_certificate(certificate: 'dummy', authenticator: authenticator)
          expect(response.success?).to be(false)
        end
      end
    end

    context 'when using HTTPS' do
      it 'connects successfully with allowed host and custom ca_cert_path' do
        client = described_class.new(
          http_client: transporter_class,
          authenticator_service_url: @https_url,
          ca_cert_path: @ca_cert_file.path,
          http_allowlist: ['localhost']
        )
        response = client.validate_certificate(certificate: 'dummy', authenticator: authenticator)
        expect(response.success?).to be(true)
        expect(response.result['attributes']['attr']).to eq('value')
      end

      it 'fails to connect with allowed host and custom ca_cert_path with an incorrect certificate' do
        client = described_class.new(
          http_client: transporter_class,
          authenticator_service_url: @https_url,
          ca_cert_path: @incorrect_ca_cert_file.path,
          http_allowlist: ['localhost']
        )
        response = client.validate_certificate(certificate: 'dummy', authenticator: authenticator)
        expect(response.success?).to be(false)
      end
    end
  end
end
