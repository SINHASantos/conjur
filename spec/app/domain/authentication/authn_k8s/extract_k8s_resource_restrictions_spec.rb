# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::ExtractK8sResourceRestrictions) do
  let(:authenticator_name) { 'authn-k8s' }
  let(:service_id) { 'service-id' }
  let(:role_name) { 'host/namespace/*/*' }
  let(:account) { 'test-account' }

  let(:extract_resource_restrictions) do
    instance_double(Authentication::ResourceRestrictions::ExtractResourceRestrictions)
  end

  let(:resource_restrictions_class) { Authentication::ResourceRestrictions::ResourceRestrictions }
  let(:logger) { instance_double(Logger, debug: nil) }

  subject do
    described_class.new(
      extract_resource_restrictions: extract_resource_restrictions,
      resource_restrictions_class: resource_restrictions_class,
      logger: logger
    )
  end

  def build_restrictions(restrictions_hash)
    Authentication::ResourceRestrictions::ResourceRestrictions.new(
      resource_restrictions_hash: restrictions_hash
    )
  end

  def call_subject(restrictions_from_annotations:)
    allow(extract_resource_restrictions)
      .to receive(:call)
      .with(
        authenticator_name: authenticator_name,
        service_id: service_id,
        role_name: role_name,
        account: account
      )
      .and_return(restrictions_from_annotations)

    subject.call(
      authenticator_name: authenticator_name,
      service_id: service_id,
      role_name: role_name,
      account: account
    )
  end

  context 'when annotations include resource restrictions' do
    it 'returns restrictions from annotations without container name' do
      restrictions_from_annotations = build_restrictions(
        Authentication::AuthnK8s::Restrictions::NAMESPACE => 'namespace',
        Authentication::AuthnK8s::Restrictions::AUTHENTICATION_CONTAINER_NAME => 'container-name'
      )

      expect(logger).not_to receive(:debug)

      result = call_subject(restrictions_from_annotations: restrictions_from_annotations)

      expect(result.names).to match_array(
        [Authentication::AuthnK8s::Restrictions::NAMESPACE]
      )
    end
  end

  context 'when annotations are empty and host id includes a resource type' do
    let(:role_name) { 'host/namespace/stateful_set/my-statefulset' }

    it 'extracts namespace and resource type from host id' do
      restrictions_from_annotations = build_restrictions({})

      expect(logger).to receive(:debug).twice

      result = call_subject(
        restrictions_from_annotations: restrictions_from_annotations
      )

      expect(result.names).to match_array(
        [
          Authentication::AuthnK8s::Restrictions::NAMESPACE,
          Authentication::AuthnK8s::Restrictions::STATEFUL_SET
        ]
      )
    end
  end

  context 'when annotations are empty and host id uses wildcards' do
    let(:role_name) { 'host/namespace/*/*' }

    it 'extracts only namespace from host id' do
      restrictions_from_annotations = build_restrictions({})

      expect(logger).to receive(:debug).twice

      result = call_subject(
        restrictions_from_annotations: restrictions_from_annotations
      )

      expect(result.names).to match_array(
        [Authentication::AuthnK8s::Restrictions::NAMESPACE]
      )
    end
  end

  context 'when annotations include only authentication container name' do
    let(:role_name) { 'host/namespace/pod/my-pod' }

    it 'falls back to host id extraction' do
      restrictions_from_annotations = build_restrictions(
        Authentication::AuthnK8s::Restrictions::AUTHENTICATION_CONTAINER_NAME => 'container-name'
      )

      expect(logger).to receive(:debug).twice

      result = call_subject(
        restrictions_from_annotations: restrictions_from_annotations
      )

      expect(result.names).to match_array(
        [
          Authentication::AuthnK8s::Restrictions::NAMESPACE,
          Authentication::AuthnK8s::Restrictions::POD
        ]
      )
    end
  end

  context 'when host id is invalid' do
    let(:role_name) { 'host/namespace/only-two' }

    it 'raises InvalidHostId' do
      restrictions_from_annotations = build_restrictions({})

      expect(logger).to receive(:debug)
        .with(kind_of(LogMessages::Authentication::AuthnK8s::ExtractingRestrictionsFromHostId))

      expect do
        call_subject(
          restrictions_from_annotations: restrictions_from_annotations
        )
      end.to raise_error(Errors::Authentication::AuthnK8s::InvalidHostId)
    end
  end
end
