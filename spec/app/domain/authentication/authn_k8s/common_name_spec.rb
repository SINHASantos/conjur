# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::CommonName) do
  describe '.from_host_resource_name' do
    it 'converts slashes to dots' do
      resource_name = 'default/deployment/myapp'
      common_name = Authentication::AuthnK8s::CommonName.from_host_resource_name(resource_name)
      expect(common_name.to_s).to eq('default.deployment.myapp')
    end

    it 'handles multiple slashes' do
      resource_name = 'namespace/kind/name/extra'
      common_name = Authentication::AuthnK8s::CommonName.from_host_resource_name(resource_name)
      expect(common_name.to_s).to eq('namespace.kind.name.extra')
    end

    it 'handles single component names' do
      resource_name = 'myhost'
      common_name = Authentication::AuthnK8s::CommonName.from_host_resource_name(resource_name)
      expect(common_name.to_s).to eq('myhost')
    end
  end

  describe '#initialize' do
    it 'accepts a common_name string' do
      common_name_str = 'default.deployment.myapp'
      expect { Authentication::AuthnK8s::CommonName.new(common_name_str) }.not_to raise_error
    end
  end

  describe '#to_s' do
    it 'returns the common name string' do
      common_name_str = 'default.deployment.myapp'
      common_name = Authentication::AuthnK8s::CommonName.new(common_name_str)
      expect(common_name.to_s).to eq(common_name_str)
    end
  end

  describe '#k8s_host_name' do
    it 'converts dots back to slashes' do
      common_name = Authentication::AuthnK8s::CommonName.new('default.deployment.myapp')
      expect(common_name.k8s_host_name).to eq('default/deployment/myapp')
    end

    it 'handles single component names' do
      common_name = Authentication::AuthnK8s::CommonName.new('myhost')
      expect(common_name.k8s_host_name).to eq('myhost')
    end

    it 'is cached after first call' do
      common_name = Authentication::AuthnK8s::CommonName.new('default.deployment.myapp')
      first_call = common_name.k8s_host_name
      second_call = common_name.k8s_host_name
      expect(first_call).to eq('default/deployment/myapp')
      expect(second_call).to eq('default/deployment/myapp')
    end
  end

  describe 'round-trip conversion' do
    it 'converts from resource name to common name and back' do
      original_resource_name = 'default/deployment/myapp'
      common_name = Authentication::AuthnK8s::CommonName.from_host_resource_name(original_resource_name)
      converted_back = common_name.k8s_host_name
      expect(converted_back).to eq(original_resource_name)
    end
  end
end
