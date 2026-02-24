# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::K8sResource) do
  describe '#initialize' do
    it 'accepts type and value parameters' do
      k8s_resource = Authentication::AuthnK8s::K8sResource.new(
        type: 'pod',
        value: 'my-pod'
      )
      expect(k8s_resource.type).to eq('pod')
      expect(k8s_resource.value).to eq('my-pod')
    end
  end

  describe '#type' do
    it 'returns the resource type' do
      k8s_resource = Authentication::AuthnK8s::K8sResource.new(
        type: 'deployment',
        value: 'my-deployment'
      )
      expect(k8s_resource.type).to eq('deployment')
    end
  end

  describe '#value' do
    it 'returns the resource value' do
      k8s_resource = Authentication::AuthnK8s::K8sResource.new(
        type: 'stateful-set',
        value: 'my-stateful-set'
      )
      expect(k8s_resource.value).to eq('my-stateful-set')
    end
  end

  describe '==' do
    it 'returns true when type and value match' do
      resource1 = Authentication::AuthnK8s::K8sResource.new(
        type: 'pod',
        value: 'my-pod'
      )
      resource2 = Authentication::AuthnK8s::K8sResource.new(
        type: 'pod',
        value: 'my-pod'
      )
      expect(resource1).to eq(resource2)
    end

    it 'returns false when type differs' do
      resource1 = Authentication::AuthnK8s::K8sResource.new(
        type: 'pod',
        value: 'my-pod'
      )
      resource2 = Authentication::AuthnK8s::K8sResource.new(
        type: 'deployment',
        value: 'my-pod'
      )
      expect(resource1).not_to eq(resource2)
    end

    it 'returns false when value differs' do
      resource1 = Authentication::AuthnK8s::K8sResource.new(
        type: 'pod',
        value: 'pod-1'
      )
      resource2 = Authentication::AuthnK8s::K8sResource.new(
        type: 'pod',
        value: 'pod-2'
      )
      expect(resource1).not_to eq(resource2)
    end

    it 'returns false when both type and value differ' do
      resource1 = Authentication::AuthnK8s::K8sResource.new(
        type: 'pod',
        value: 'pod-1'
      )
      resource2 = Authentication::AuthnK8s::K8sResource.new(
        type: 'deployment',
        value: 'deployment-1'
      )
      expect(resource1).not_to eq(resource2)
    end
  end
end
