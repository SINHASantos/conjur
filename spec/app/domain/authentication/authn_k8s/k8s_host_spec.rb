# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::K8sHost) do
  let(:account) { 'test-account' }
  let(:service_name) { 'authn-k8s' }
  let(:common_name) { 'host.default.deployment.myapp' }
  let(:logger) { instance_double(Logger, debug: nil) }

  before do
    allow(Rails).to receive(:logger).and_return(logger)
  end

  describe '.from_csr' do
    context 'when CSR includes a common name' do
      let(:csr) do
        instance_double(
          Util::OpenSsl::X509::SmartCsr,
          common_name: common_name,
          subject_to_s: 'CSR Subject',
          spiffe_id: 'spiffe://cluster.local/ns/default/pod/app'
        )
      end

      it 'builds a host from the CSR' do
        host = described_class.from_csr(
          account: account,
          service_name: service_name,
          csr: csr
        )

        expect(host.k8s_host_name).to eq('host/default/deployment/myapp')
        expect(host.conjur_host_id).to eq(
          "#{account}:host:default/deployment/myapp"
        )
      end
    end

    context 'when CSR is missing a common name' do
      let(:csr) do
        instance_double(
          Util::OpenSsl::X509::SmartCsr,
          common_name: nil,
          subject_to_s: 'CSR Subject',
          spiffe_id: 'spiffe://cluster.local/ns/default/pod/app'
        )
      end

      it 'raises CSRMissingCNEntry' do
        expect do
          described_class.from_csr(
            account: account,
            service_name: service_name,
            csr: csr
          )
        end.to raise_error(
          Errors::Authentication::AuthnK8s::CSRMissingCNEntry
        )
      end
    end
  end

  describe '.from_cert' do
    context 'when cert includes a common name' do
      let(:cert) do
        Util::OpenSsl::X509::Certificate.from_subject(
          subject: "/CN=#{common_name}"
        )
      end

      it 'builds a host from the certificate' do
        host = described_class.from_cert(
          account: account,
          service_name: service_name,
          cert: cert
        )

        expect(host.k8s_host_name).to eq('host/default/deployment/myapp')
      end
    end

    context 'when cert is missing a common name' do
      let(:cert) do
        Util::OpenSsl::X509::Certificate.from_subject(
          subject: '/OU=NoCN/O=conjur'
        )
      end

      it 'raises CertMissingCNEntry' do
        expect do
          described_class.from_cert(
            account: account,
            service_name: service_name,
            cert: cert
          )
        end.to raise_error(
          Errors::Authentication::AuthnK8s::CertMissingCNEntry
        )
      end
    end
  end

  describe '#conjur_host_id' do
    it 'returns the account-scoped host id derived from the common name' do
      host = described_class.new(
        account: account,
        service_name: service_name,
        common_name: common_name
      )

      expect(host.conjur_host_id).to eq(
        "#{account}:host:default/deployment/myapp"
      )
    end
  end

  describe '#k8s_host_name' do
    it 'returns the kubernetes host name derived from the common name' do
      host = described_class.new(
        account: account,
        service_name: service_name,
        common_name: common_name
      )

      expect(host.k8s_host_name).to eq('host/default/deployment/myapp')
    end
  end
end
