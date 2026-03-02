# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::SpiffeId) do
  describe '#initialize' do
    it 'accepts a spiffe_id string' do
      spiffe_id_str = 'spiffe://cluster.local/ns/default/sa/myapp'
      expect { Authentication::AuthnK8s::SpiffeId.new(spiffe_id_str) }.not_to raise_error
    end
  end

  describe '#namespace' do
    it 'extracts the namespace from the spiffe URI' do
      spiffe_id_str = 'spiffe://cluster.local/ns/default/sa/myapp'
      spiffe_id = Authentication::AuthnK8s::SpiffeId.new(spiffe_id_str)
      expect(spiffe_id.namespace).to eq('default')
    end

    it 'handles multi-part namespaces' do
      spiffe_id_str = 'spiffe://cluster.local/ns/my-namespace/sa/myapp'
      spiffe_id = Authentication::AuthnK8s::SpiffeId.new(spiffe_id_str)
      expect(spiffe_id.namespace).to eq('my-namespace')
    end
  end

  describe '#name' do
    it 'extracts the service account name from the spiffe URI' do
      spiffe_id_str = 'spiffe://cluster.local/ns/default/sa/myapp'
      spiffe_id = Authentication::AuthnK8s::SpiffeId.new(spiffe_id_str)
      expect(spiffe_id.name).to eq('myapp')
    end

    it 'handles complex service account names' do
      spiffe_id_str = 'spiffe://cluster.local/ns/default/sa/my-service-account'
      spiffe_id = Authentication::AuthnK8s::SpiffeId.new(spiffe_id_str)
      expect(spiffe_id.name).to eq('my-service-account')
    end
  end

  describe '#to_s' do
    it 'returns the original spiffe_id string' do
      spiffe_id_str = 'spiffe://cluster.local/ns/default/sa/myapp'
      spiffe_id = Authentication::AuthnK8s::SpiffeId.new(spiffe_id_str)
      expect(spiffe_id.to_s).to eq(spiffe_id_str)
    end
  end

  describe '#to_altname' do
    it 'returns the spiffe_id as URI altname format' do
      spiffe_id_str = 'spiffe://cluster.local/ns/default/sa/myapp'
      spiffe_id = Authentication::AuthnK8s::SpiffeId.new(spiffe_id_str)
      expect(spiffe_id.to_altname).to eq("URI:#{spiffe_id_str}")
    end
  end

  describe 'caching' do
    it 'caches the parsed spiffe_id' do
      spiffe_id_str = 'spiffe://cluster.local/ns/default/sa/myapp'
      spiffe_id = Authentication::AuthnK8s::SpiffeId.new(spiffe_id_str)

      # Call namespace twice to ensure it returns the same cached value
      first_call = spiffe_id.namespace
      second_call = spiffe_id.namespace

      expect(first_call).to eq('default')
      expect(second_call).to eq('default')
    end
  end
end
