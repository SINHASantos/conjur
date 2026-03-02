# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::Authenticator) do
  let(:service_id) { 'my-service' }
  let(:account) { 'my-account' }
  let(:username) { 'default/deployment/myapp' }
  let(:authenticator_name) { 'authn-k8s' }
  let(:request_env) { { 'HTTP_X_SSL_CLIENT_CERTIFICATE' => header_cert } }
  let(:request) { instance_double(ActionDispatch::Request, env: request_env) }
  let(:header_cert) { CGI.escape('cert-bytes') }

  let(:authenticator_input) do
    instance_double(
      Authentication::AuthenticatorInput,
      service_id: service_id,
      authenticator_name: authenticator_name,
      account: account,
      username: username,
      request: request
    )
  end

  let(:validate_pod_request) do
    instance_double(Authentication::AuthnK8s::ValidatePodRequest)
  end

  let(:cert) do
    double(
      'SmartCert',
      common_name: 'default.deployment.myapp',
      san_uri: 'spiffe://cluster.local/ns/default/pod/myapp',
      not_after: Time.now + 3600
    )
  end

  let(:webservice_ca) { instance_double(Util::OpenSsl::CA, verify: true) }
  let(:k8s_host) { instance_double(Authentication::AuthnK8s::K8sHost) }

  subject do
    described_class.new(validate_pod_request: validate_pod_request)
  end

  before do
    allow(validate_pod_request).to receive(:call)
    allow(Util::OpenSsl::X509::SmartCert).to receive(:new).and_return(cert)
    allow(Repos::ConjurCA).to receive(:ca).and_return(webservice_ca)
    allow(Authentication::AuthnK8s::K8sHost).to receive(:from_cert).and_return(k8s_host)
  end

  describe '#call' do
    context 'when the request is valid' do
      it 'returns true after validations' do
        result = subject.call(authenticator_input: authenticator_input)
        expect(result).to be(true)
      end
    end

    context 'when client certificate is missing' do
      let(:header_cert) { nil }

      it 'raises MissingClientCertificate' do
        expect do
          subject.call(authenticator_input: authenticator_input)
        end.to raise_error(Errors::Authentication::AuthnK8s::MissingClientCertificate)
      end
    end

    context 'when CA cannot verify the cert' do
      let(:webservice_ca) { instance_double(Util::OpenSsl::CA, verify: false) }

      it 'raises UntrustedClientCertificate' do
        expect do
          subject.call(authenticator_input: authenticator_input)
        end.to raise_error(Errors::Authentication::AuthnK8s::UntrustedClientCertificate)
      end
    end

    context 'when common name does not match host' do
      let(:cert) do
        double(
          'SmartCert',
          common_name: 'default.deployment.other',
          san_uri: 'spiffe://cluster.local/ns/default/pod/myapp',
          not_after: Time.now + 3600
        )
      end

      it 'raises CommonNameDoesntMatchHost' do
        expect do
          subject.call(authenticator_input: authenticator_input)
        end.to raise_error(Errors::Authentication::AuthnK8s::CommonNameDoesntMatchHost)
      end
    end

    context 'when the cert is expired' do
      let(:cert) do
        double(
          'SmartCert',
          common_name: 'default.deployment.myapp',
          san_uri: 'spiffe://cluster.local/ns/default/pod/myapp',
          not_after: Time.now - 1
        )
      end

      it 'raises ClientCertificateExpired' do
        expect do
          subject.call(authenticator_input: authenticator_input)
        end.to raise_error(Errors::Authentication::AuthnK8s::ClientCertificateExpired)
      end
    end

    context 'when calling the pod request validator' do
      it 'passes a PodRequest to ValidatePodRequest' do
        subject.call(authenticator_input: authenticator_input)
        expect(validate_pod_request).to have_received(:call) do |args|
          expect(args[:pod_request]).to be_a(Authentication::AuthnK8s::PodRequest)
        end
      end
    end
  end

  describe '#valid?' do
    it 'delegates to call with authenticator_input' do
      allow(subject).to receive(:call).and_return(true)
      expect(subject.valid?(authenticator_input)).to be(true)
    end
  end

  describe '#status' do
    let(:status_input) do
      instance_double(
        Authentication::AuthenticatorStatusInput,
        account: account,
        service_id: service_id
      )
    end

    it 'delegates to ValidateStatus' do
      validate_status = double('ValidateStatus', call: true)
      allow(Authentication::AuthnK8s::ValidateStatus).to receive(:new).and_return(validate_status)

      expect(subject.status(authenticator_status_input: status_input)).to be(true)
    end
  end
end
