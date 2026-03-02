# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::Restrictions) do
  describe 'constants' do
    it 'defines AUTHENTICATOR_NAME' do
      expect(Authentication::AuthnK8s::AUTHENTICATOR_NAME).to eq('authn-k8s')
    end

    it 'defines REQUIRED_VARIABLE_NAMES' do
      expected_vars = %w[ca/cert ca/key]
      expect(Authentication::AuthnK8s::REQUIRED_VARIABLE_NAMES).to eq(expected_vars)
    end

    it 'defines OPTIONAL_VARIABLE_NAMES' do
      expected_vars = %w[
        kubernetes/ca-cert
        kubernetes/api-url
        kubernetes/service-account-token
      ]
      expect(Authentication::AuthnK8s::OPTIONAL_VARIABLE_NAMES).to eq(expected_vars)
    end
  end

  describe 'restriction types' do
    it 'defines NAMESPACE restriction' do
      expect(Authentication::AuthnK8s::Restrictions::NAMESPACE).to eq('namespace')
    end

    it 'defines NAMESPACE_LABEL_SELECTOR restriction' do
      expect(Authentication::AuthnK8s::Restrictions::NAMESPACE_LABEL_SELECTOR).to eq('namespace-label-selector')
    end

    it 'defines SERVICE_ACCOUNT restriction' do
      expect(Authentication::AuthnK8s::Restrictions::SERVICE_ACCOUNT).to eq('service-account')
    end

    it 'defines POD restriction' do
      expect(Authentication::AuthnK8s::Restrictions::POD).to eq('pod')
    end

    it 'defines DEPLOYMENT restriction' do
      expect(Authentication::AuthnK8s::Restrictions::DEPLOYMENT).to eq('deployment')
    end

    it 'defines STATEFUL_SET restriction' do
      expect(Authentication::AuthnK8s::Restrictions::STATEFUL_SET).to eq('stateful-set')
    end

    it 'defines DEPLOYMENT_CONFIG restriction' do
      expect(Authentication::AuthnK8s::Restrictions::DEPLOYMENT_CONFIG).to eq('deployment-config')
    end

    it 'defines AUTHENTICATION_CONTAINER_NAME restriction' do
      expect(Authentication::AuthnK8s::Restrictions::AUTHENTICATION_CONTAINER_NAME).to eq('authentication-container-name')
    end
  end

  describe 'restriction constraint lists' do
    it 'defines REQUIRED_EXCLUSIVE as namespace and namespace-label-selector' do
      expected = [
        Authentication::AuthnK8s::Restrictions::NAMESPACE,
        Authentication::AuthnK8s::Restrictions::NAMESPACE_LABEL_SELECTOR
      ]
      expect(Authentication::AuthnK8s::Restrictions::REQUIRED_EXCLUSIVE).to eq(expected)
    end

    it 'defines RESOURCE_TYPE_EXCLUSIVE as deployment types' do
      expected = [
        Authentication::AuthnK8s::Restrictions::DEPLOYMENT,
        Authentication::AuthnK8s::Restrictions::DEPLOYMENT_CONFIG,
        Authentication::AuthnK8s::Restrictions::STATEFUL_SET
      ]
      expect(Authentication::AuthnK8s::Restrictions::RESOURCE_TYPE_EXCLUSIVE).to eq(expected)
    end

    it 'defines OPTIONAL as service_account, pod, and container name' do
      expected = [
        Authentication::AuthnK8s::Restrictions::SERVICE_ACCOUNT,
        Authentication::AuthnK8s::Restrictions::POD,
        Authentication::AuthnK8s::Restrictions::AUTHENTICATION_CONTAINER_NAME
      ]
      expect(Authentication::AuthnK8s::Restrictions::OPTIONAL).to eq(expected)
    end

    it 'defines PERMITTED as all restrictions combined' do
      expect(Authentication::AuthnK8s::Restrictions::PERMITTED).to include(
        *Authentication::AuthnK8s::Restrictions::REQUIRED_EXCLUSIVE,
        *Authentication::AuthnK8s::Restrictions::RESOURCE_TYPE_EXCLUSIVE,
        *Authentication::AuthnK8s::Restrictions::OPTIONAL
      )
    end
  end

  describe 'CONSTRAINTS' do
    it 'defines CONSTRAINTS as a MultipleConstraint' do
      expect(Authentication::AuthnK8s::Restrictions::CONSTRAINTS).to be_a(
        Authentication::Constraints::MultipleConstraint
      )
    end
  end
end
