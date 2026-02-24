# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::PodRequest) do
  let(:service_id) { 'my-k8s' }
  let(:k8s_host) { double('K8sHost') }
  let(:spiffe_id) { double('SpiffeId') }

  subject do
    Authentication::AuthnK8s::PodRequest.new(
      service_id: service_id,
      k8s_host: k8s_host,
      spiffe_id: spiffe_id
    )
  end

  describe '#service_id' do
    it 'returns the service_id passed to the initializer' do
      expect(subject.service_id).to eq(service_id)
    end
  end

  describe '#k8s_host' do
    it 'returns the k8s_host passed to the initializer' do
      expect(subject.k8s_host).to eq(k8s_host)
    end
  end

  describe '#spiffe_id' do
    it 'returns the spiffe_id passed to the initializer' do
      expect(subject.spiffe_id).to eq(spiffe_id)
    end
  end

  describe 'initialization' do
    it 'requires all parameters' do
      expect do
        Authentication::AuthnK8s::PodRequest.new(
          service_id: service_id,
          k8s_host: k8s_host
        )
      end.to raise_error(ArgumentError)
    end
  end
end
