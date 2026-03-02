# frozen_string_literal: true

require 'spec_helper'

describe(Authentication::AuthnK8s::ValidateStatus) do
  subject do
    Authentication::AuthnK8s::ValidateStatus.new(
      fetch_authenticator_secrets: fetch_authenticator_secrets_double
    )
  end

  let(:fetch_authenticator_secrets_double) do
    instance_double(
      Authentication::Util::FetchAuthenticatorSecrets
    ).tap do |double|
      allow(double)
        .to receive(:call)
        .with(
          conjur_account: account,
          service_id: service_id,
          authenticator_name: \
            Authentication::AuthnK8s::AUTHENTICATOR_NAME,
          required_variable_names: \
            Authentication::AuthnK8s::REQUIRED_VARIABLE_NAMES
        )
        .and_return(authenticator_secrets)
    end
  end

  let(:authenticator_secrets) do
    {
      'kubernetes/service-account-token' => k8s_service_account_token,
      'kubernetes/ca-cert' => k8s_ca_certificate_pem,
      'kubernetes/api-url' => k8s_api_url,
      'ca/cert' => conjur_ca_certificate_pem,
      'ca/key' => conjur_ca_private_key_pem
    }
  end

  let(:k8s_service_account_token) do
    JWT.encode({ data: 'test' }, nil, 'none')
  end

  let(:k8s_ca_certificate_pem) { k8s_ca_certificate.to_pem }
  let(:k8s_ca_certificate) do
    Util::OpenSsl::X509::Certificate.from_subject(
      subject: 'CN=Test CA'
    )
  end

  let(:k8s_api_url) do
    "https://#{k8s_api_host}#{":#{k8s_api_port}" if k8s_api_port}"
  end
  let(:k8s_api_host) { 'valid_url' }
  let(:k8s_api_port) { nil }

  let(:conjur_ca_certificate_pem) { conjur_ca_certificate.to_pem }
  let(:conjur_ca_certificate) do
    Util::OpenSsl::X509::Certificate.from_subject(
      subject: 'CN=Conjur Issuing CA',
      key: conjur_ca_private_key,
      extensions: conjur_ca_certificate_extensions,
      good_for: conjur_ca_certificate_good_for
    )
  end
  let(:conjur_ca_certificate_extensions) do
    [
      ['basicConstraints', 'CA:TRUE', true],
      ['keyUsage', 'keyCertSign', true]
    ]
  end
  let(:conjur_ca_certificate_good_for) { 10.years }

  let(:conjur_ca_private_key_pem) { conjur_ca_private_key.to_pem }
  let(:conjur_ca_private_key) do
    OpenSSL::PKey::RSA.new(2048)
  end

  let(:account) { 'rspec' }
  let(:service_id) { 'test'}

  let(:kubernetes_api_response_code) { 200 }

  before do
    # We'll place expectations on these later, so allow other calls for the
    # file as a whole.
    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:read).and_call_original
    allow(ENV).to receive(:[]).and_call_original

    # Stub the HTTP calls to the Kubernetes API
    stub_request(:get, "#{k8s_api_url.strip}/apis")
      .with(
        headers: {
          'Accept' => 'application/json',
          'Accept-Encoding' => /^.*$/,
          'Authorization' => "Bearer #{k8s_service_account_token.strip}",
          'Host' => "#{k8s_api_host}#{":#{k8s_api_port}" if k8s_api_port}",
          'User-Agent' => %r{^rest-client/.*$}
        }
      )
      .to_return(status: kubernetes_api_response_code, body: "", headers: {})
  end

  shared_examples_for 'raises an error' do |error_class, error_message|
    it 'raises an error' do
      expect do
        subject.call(account: account, service_id: service_id)
      end.to raise_error(error_class, error_message)
    end
  end

  shared_examples_for 'does not raise an error' do
    it 'does not raise an error' do
      expect do
        subject.call(account: account, service_id: service_id)
      end.not_to raise_error
    end
  end

  context 'when configured correctly' do
    include_examples 'does not raise an error'
  end

  context 'when the access token is empty' do
    let(:k8s_service_account_token) { '' }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidServiceAccountToken,
      "CONJ00153E Invalid service account token: " \
        "Unable to decode JWT: Not enough or too many segments"
    )
  end

  context 'when the access token file is present' do
    # Remove the token from the authenticator secrets so it can only succeed
    # with the file.
    let(:authenticator_secrets) do
      {
        'kubernetes/ca-cert' => k8s_ca_certificate_pem,
        'kubernetes/api-url' => k8s_api_url,
        'ca/cert' => conjur_ca_certificate_pem,
        'ca/key' => conjur_ca_private_key_pem
      }
    end

    before do
      allow(File)
        .to receive(:exist?)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_TOKEN_PATH)
        .and_return(true)

      allow(File)
        .to receive(:read)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_TOKEN_PATH)
        .and_return(k8s_service_account_token)
    end

    include_examples 'does not raise an error'
  end

  context 'when the access token is present in policy but nil' do
    # Token key exists but value is nil - should fall back to file
    let(:authenticator_secrets) do
      {
        'kubernetes/service-account-token' => nil,
        'kubernetes/ca-cert' => k8s_ca_certificate_pem,
        'kubernetes/api-url' => k8s_api_url,
        'ca/cert' => conjur_ca_certificate_pem,
        'ca/key' => conjur_ca_private_key_pem
      }
    end

    before do
      allow(File)
        .to receive(:exist?)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_TOKEN_PATH)
        .and_return(true)

      allow(File)
        .to receive(:read)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_TOKEN_PATH)
        .and_return(k8s_service_account_token)
    end

    include_examples 'does not raise an error'
  end

  context 'when the access token has leading whitespace' do
    let(:k8s_service_account_token) do
      "\r\n#{JWT.encode({ data: 'test' }, nil, 'none')}"
    end

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidServiceAccountToken,
      "CONJ00153E Invalid service account token: " \
        "Invalid characters in token: \n, \r"
    )
  end

  context 'when the access token has trailing whitespace' do
    let(:k8s_service_account_token) do
      "#{JWT.encode({ data: 'test' }, nil, 'none')}\r\n"
    end

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidServiceAccountToken,
      "CONJ00153E Invalid service account token: " \
        "Invalid characters in token: \n, \r"
    )
  end

  context 'when the kubernetes API returns 401 unauthorized' do
    let(:kubernetes_api_response_code) { 401 }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidServiceAccountToken,
      "CONJ00153E Invalid service account token: 401 Unauthorized"
    )
  end

  context 'when the kubernetes API returns 403 Forbidden' do
    let(:kubernetes_api_response_code) { 403 }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidServiceAccountToken,
      "CONJ00153E Invalid service account token: " \
        "Service account is unauthorized to perform API discovery: " \
        "403 Forbidden. Ensure the 'system:discovery' role is bound to " \
        "service account"
    )
  end

  context 'when the API url is empty' do
    let(:k8s_api_url) { '' }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidApiUrl,
      "CONJ00042E Received invalid Kubernetes API url: ''"
    )
  end

  context 'when the API url is configured in the environment' do
    # Remove the API URL from the authenticator secrets so it can only succeed
    # using the environment variables
    let(:authenticator_secrets) do
      {
        'kubernetes/service-account-token' => k8s_service_account_token,
        'kubernetes/ca-cert' => k8s_ca_certificate_pem,
        'ca/cert' => conjur_ca_certificate_pem,
        'ca/key' => conjur_ca_private_key_pem
      }
    end

    let(:k8s_api_host) { 'k8s_host' }
    let(:k8s_api_port) { '8443' }

    before do
      allow(ENV)
        .to receive(:[])
        .with('KUBERNETES_SERVICE_HOST')
        .and_return(k8s_api_host)

      allow(ENV)
        .to receive(:[])
        .with('KUBERNETES_SERVICE_PORT')
        .and_return(k8s_api_port)
    end

    include_examples 'does not raise an error'
  end

  context 'when the API url is present in policy but nil' do
    # API URL key exists but value is nil - should fall back to environment
    let(:authenticator_secrets) do
      {
        'kubernetes/service-account-token' => k8s_service_account_token,
        'kubernetes/ca-cert' => k8s_ca_certificate_pem,
        'kubernetes/api-url' => nil,
        'ca/cert' => conjur_ca_certificate_pem,
        'ca/key' => conjur_ca_private_key_pem
      }
    end

    let(:k8s_api_host) { 'k8s_host' }
    let(:k8s_api_port) { '8443' }

    before do
      allow(ENV)
        .to receive(:[])
        .with('KUBERNETES_SERVICE_HOST')
        .and_return(k8s_api_host)

      allow(ENV)
        .to receive(:[])
        .with('KUBERNETES_SERVICE_PORT')
        .and_return(k8s_api_port)

      # Re-stub the HTTP request with the environment-based URL
      stub_request(:get, "https://#{k8s_api_host}:#{k8s_api_port}/apis")
        .with(
          headers: {
            'Accept' => 'application/json',
            'Accept-Encoding' => /^.*$/,
            'Authorization' => "Bearer #{k8s_service_account_token.strip}",
            'Host' => "#{k8s_api_host}:#{k8s_api_port}",
            'User-Agent' => %r{^rest-client/.*$}
          }
        )
        .to_return(status: 200, body: "", headers: {})
    end

    include_examples 'does not raise an error'
  end

  context 'when both policy API url and environment API url are set' do
    # Both sources present - policy should take precedence
    let(:k8s_api_host) { 'policy_api_host' }
    let(:k8s_api_port) { '9443' }
    let(:env_api_host) { 'different_env_host' }
    let(:env_api_port) { '7443' }

    before do
      allow(ENV)
        .to receive(:[]).and_call_original
      allow(ENV)
        .to receive(:[])
        .with('KUBERNETES_SERVICE_HOST')
        .and_return(env_api_host)

      allow(ENV)
        .to receive(:[])
        .with('KUBERNETES_SERVICE_PORT')
        .and_return(env_api_port)

      # Stub the HTTP call using the policy-configured URL (desired behavior)
      stub_request(:get, "https://#{k8s_api_host}:#{k8s_api_port}/apis")
        .with(
          headers: {
            'Accept' => 'application/json',
            'Accept-Encoding' => /^.*$/,
            'Authorization' => "Bearer #{k8s_service_account_token.strip}",
            'Host' => "#{k8s_api_host}:#{k8s_api_port}",
            'User-Agent' => %r{^rest-client/.*$}
          }
        )
        .to_return(status: 200, body: "", headers: {})
    end

    it 'uses the policy config instead of environment variables' do
      # Policy kubernetes/api-url should take precedence over KUBERNETES_SERVICE_HOST
      expect do
        subject.call(account: account, service_id: service_id)
      end.not_to raise_error
    end
  end

  context 'when both policy CA cert and file CA cert are set' do
    # Both sources present - policy should take precedence
    let(:file_ca_certificate) do
      Util::OpenSsl::X509::Certificate.from_subject(
        subject: 'CN=File CA'
      )
    end

    before do
      allow(File)
        .to receive(:exist?).and_call_original
      allow(File)
        .to receive(:exist?)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_CA_PATH)
        .and_return(true)

      allow(File)
        .to receive(:read).and_call_original
      allow(File)
        .to receive(:read)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_CA_PATH)
        .and_return(file_ca_certificate.to_pem)

      # Stub the HTTP call using the policy-configured token and URL
      stub_request(:get, "#{k8s_api_url.strip}/apis")
        .with(
          headers: {
            'Accept' => 'application/json',
            'Accept-Encoding' => /^.*$/,
            'Authorization' => "Bearer #{k8s_service_account_token.strip}",
            'Host' => "#{k8s_api_host}#{":#{k8s_api_port}" if k8s_api_port}",
            'User-Agent' => %r{^rest-client/.*$}
          }
        )
        .to_return(status: 200, body: "", headers: {})
    end

    it 'uses the policy CA cert instead of file-based cert' do
      # Policy kubernetes/ca-cert should take precedence over mounted certificate file
      expect do
        subject.call(account: account, service_id: service_id)
      end.not_to raise_error
    end
  end

  context 'when the CA cert is present in policy but nil' do
    # CA cert key exists but value is nil - should fall back to file
    let(:authenticator_secrets) do
      {
        'kubernetes/service-account-token' => k8s_service_account_token,
        'kubernetes/ca-cert' => nil,
        'kubernetes/api-url' => k8s_api_url,
        'ca/cert' => conjur_ca_certificate_pem,
        'ca/key' => conjur_ca_private_key_pem
      }
    end

    let(:file_ca_certificate) do
      Util::OpenSsl::X509::Certificate.from_subject(
        subject: 'CN=File CA'
      )
    end

    before do
      allow(File)
        .to receive(:exist?).and_call_original
      allow(File)
        .to receive(:exist?)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_CA_PATH)
        .and_return(true)

      allow(File)
        .to receive(:read).and_call_original
      allow(File)
        .to receive(:read)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_CA_PATH)
        .and_return(file_ca_certificate.to_pem)
    end

    include_examples 'does not raise an error'
  end

  context 'when both policy service account token and file token are set' do
    # Both sources present - policy should take precedence
    let(:file_service_token) { JWT.encode({ data: 'file_token' }, nil, 'none') }

    before do
      allow(File)
        .to receive(:exist?).and_call_original
      allow(File)
        .to receive(:exist?)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_TOKEN_PATH)
        .and_return(true)

      allow(File)
        .to receive(:read).and_call_original
      allow(File)
        .to receive(:read)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_TOKEN_PATH)
        .and_return(file_service_token)

      # Stub the HTTP call using the policy-configured token (desired behavior)
      stub_request(:get, "#{k8s_api_url.strip}/apis")
        .with(
          headers: {
            'Accept' => 'application/json',
            'Accept-Encoding' => /^.*$/,
            'Authorization' => "Bearer #{k8s_service_account_token.strip}",
            'Host' => "#{k8s_api_host}#{":#{k8s_api_port}" if k8s_api_port}",
            'User-Agent' => %r{^rest-client/.*$}
          }
        )
        .to_return(status: 200, body: "", headers: {})
    end

    it 'uses the policy token instead of file-based token' do
      # Policy kubernetes/service-account-token should take precedence over mounted token file
      expect do
        subject.call(account: account, service_id: service_id)
      end.not_to raise_error
    end
  end

  context 'when the API url is invalid' do
    let(:k8s_api_url) { 'not a url' }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidApiUrl,
      "CONJ00042E Received invalid Kubernetes API url: 'not a url'"
    )
  end

  context 'when the API url has leading whitespace' do
    let(:k8s_api_url) { "\r\nhttp://server" }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidApiUrl,
      "CONJ00042E Received invalid Kubernetes API url: '\r\nhttp://server'"
    )
  end

  context 'when the API url has trailing whitespace' do
    let(:k8s_api_url) { "http://server\r\n" }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidApiUrl,
      "CONJ00042E Received invalid Kubernetes API url: 'http://server\r\n'"
    )
  end

  context 'when the API CA policy variable is blank (empty string)' do
    # An empty string is treated as unconfigured; falls through to file,
    # then raises RequiredResourceMissing when no file is present either.
    let(:k8s_ca_certificate_pem) { '' }

    include_examples(
      'raises an error',
      Errors::Conjur::RequiredResourceMissing,
      "CONJ00036E Missing required resource: kubernetes/ca-cert"
    )
  end

  context 'when the API CA is expired' do
    let(:k8s_ca_certificate) do
      Util::OpenSsl::X509::Certificate.from_subject(
        subject: 'CN=Test CA',
        good_for: -1.day
      )
    end

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidApiCert,
      "CONJ00154E Invalid Kubernetes API CA certificate: " \
        "Certificate has expired: /CN=Test CA"
    )
  end

  context 'when the API CA file is present' do
    # Remove the API CA from the authenticator secrets so it can only succeed
    # with the file.
    let(:authenticator_secrets) do
      {
        'kubernetes/service-account-token' => k8s_service_account_token,
        'kubernetes/api-url' => k8s_api_url,
        'ca/cert' => conjur_ca_certificate_pem,
        'ca/key' => conjur_ca_private_key_pem
      }
    end

    before do
      allow(File)
        .to receive(:exist?)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_CA_PATH)
        .and_return(true)

      allow(File)
        .to receive(:read)
        .with(Authentication::AuthnK8s::SERVICEACCOUNT_CA_PATH)
        .and_return(k8s_ca_certificate_pem)
    end

    include_examples 'does not raise an error'
  end

  context 'when the API CA is not a valid certificate' do
    let(:k8s_ca_certificate_pem) { 'test' }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidApiCert,
      "CONJ00154E Invalid Kubernetes API CA certificate: " \
        "Unable to read certificate: PEM_read_bio_X509: no start line (Expecting: CERTIFICATE)"
    )
  end

  context 'when the API CA has leading whitespace' do
    let(:k8s_ca_certificate_pem) { "\r\n#{k8s_ca_certificate.to_pem}" }

    include_examples 'does not raise an error'
  end

  context 'when the API CA has trailing whitespace' do
    let(:k8s_ca_certificate_pem) { "#{k8s_ca_certificate.to_pem}\r\n" }

    include_examples 'does not raise an error'
  end

  context 'when the Conjur signing certificate is empty' do
    let(:conjur_ca_certificate_pem) { '' }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidSigningCert,
      "CONJ00155E Invalid signing certificate: " \
        "Unable to read certificate: PEM_read_bio_X509: no start line (Expecting: CERTIFICATE)"
    )
  end

  context 'when the Conjur signing certificate is not a valid certificate' do
    let(:conjur_ca_certificate_pem) { 'test' }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidSigningCert,
      "CONJ00155E Invalid signing certificate: " \
        "Unable to read certificate: PEM_read_bio_X509: no start line (Expecting: CERTIFICATE)"
    )
  end

  context 'when the Conjur signing certificate has leading whitespace' do
    let(:conjur_ca_certificate_pem) { "\r\n#{conjur_ca_certificate.to_pem}" }

    include_examples 'does not raise an error'
  end

  context 'when the Conjur signing certificate has trailing whitespace' do
    let(:conjur_ca_certificate_pem) { "#{conjur_ca_certificate.to_pem}\r\n" }

    include_examples 'does not raise an error'
  end

  context 'when the Conjur signing certificate is expired' do
    # Certificate expired yesterday
    let(:conjur_ca_certificate_good_for) { -1.day }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidSigningCert,
      "CONJ00155E Invalid signing certificate: " \
        "Certificate has expired"
    )
  end

  context 'when the Conjur signing certificate is not a CA' do
    let(:conjur_ca_certificate_extensions) do
      [
        # CA:FALSE instead of CA:TRUE
        ['basicConstraints', 'CA:FALSE', true],
        ['keyUsage', 'keyCertSign', true]
      ]
    end

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidSigningCert,
      "CONJ00155E Invalid signing certificate: " \
        "Certificate does not include basicConstraints attribute: CA:TRUE"
    )
  end

  context 'when the Conjur signing certificate holds multiple certificates' do
    let(:conjur_ca_certificate_pem) do
      [conjur_ca_certificate.to_pem, conjur_ca_certificate.to_pem].join('\r\n')
    end

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidSigningCert,
      "CONJ00155E Invalid signing certificate: " \
        "Value contains multiple certificates. " \
        "Only a single signing certificate allowed"
    )
  end

  context 'when the Conjur signing certificate is not authorized to sign certificates' do
    let(:conjur_ca_certificate_extensions) do
      [
        ['basicConstraints', 'CA:TRUE', true],
        # The key usage doesn't contain 'keyCertSign'
        ['keyUsage', 'digitalSignature', true]
      ]
    end

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidSigningCert,
      "CONJ00155E Invalid signing certificate: " \
        "Certificate does not include keyUsage attribute: 'Certificate Sign'"
    )
  end

  context 'when the Conjur signing key and certificate do not match' do
    let(:conjur_ca_certificate) do
      # Issue the certificate with a new generated private key
      Util::OpenSsl::X509::Certificate.from_subject(
        subject: 'CN=Conjur Issuing CA',
        extensions: conjur_ca_certificate_extensions,
        good_for: conjur_ca_certificate_good_for
      )
    end

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidSigningCert,
      "CONJ00155E Invalid signing certificate: " \
        "Certificate and private key do not match"
    )
  end

  context 'when the Conjur signing key is empty' do
    let(:conjur_ca_private_key_pem) { '' }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidSigningKey,
      "CONJ00156E Invalid signing key: " \
        "Unable to read private key"
    )
  end

  context 'when the Conjur signing key is invalid' do
    let(:conjur_ca_private_key_pem) { 'test' }

    include_examples(
      'raises an error',
      Errors::Authentication::AuthnK8s::InvalidSigningKey,
      "CONJ00156E Invalid signing key: " \
        "Unable to read private key"
    )
  end

  context 'when the Conjur signing key has leading whitespace' do
    let(:conjur_ca_private_key_pem) { "\r\n#{conjur_ca_private_key.to_pem}" }

    include_examples 'does not raise an error'
  end

  context 'when the Conjur signing key has trailing whitespace' do
    let(:conjur_ca_private_key_pem) { "#{conjur_ca_private_key.to_pem}\r\n" }

    include_examples 'does not raise an error'
  end

  context 'when an SSL cert directory is configured' do
    around do |example|
      original_ssl_cert_directory = ENV['SSL_CERT_DIRECTORY']
      ENV['SSL_CERT_DIRECTORY'] = '/path/to/cert/directory'
      example.run
      ENV['SSL_CERT_DIRECTORY'] = original_ssl_cert_directory
    end

    it 'loads the additional certificates' do
      expect(Conjur::Certificates::CertUtils).to receive(:load_certificates)
        .with(anything, '/path/to/cert/directory/ca')

      subject.call(account: account, service_id: service_id)
    end
  end
end
