# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::AuthenticationRequest) do
  let(:k8s_resource_validator) { double('k8s_resource_validator') }
  let(:namespace) { 'default' }

  subject do
    described_class.new(
      namespace: namespace,
      k8s_resource_validator: k8s_resource_validator
    )
  end

  describe '#valid_restriction?' do
    context 'when restriction is NAMESPACE' do
      let(:restriction) do
        double('restriction', name: Authentication::AuthnK8s::Restrictions::NAMESPACE, value: 'default')
      end

      context 'and namespace matches' do
        it 'returns true' do
          expect(subject.valid_restriction?(restriction)).to be(true)
        end
      end

      context 'and namespace does not match' do
        let(:restriction) do
          double('restriction', name: Authentication::AuthnK8s::Restrictions::NAMESPACE, value: 'other-namespace')
        end

        it 'raises NamespaceMismatch error' do
          expect do
            subject.valid_restriction?(restriction)
          end.to raise_error(
            ::Errors::Authentication::AuthnK8s::NamespaceMismatch
          )
        end
      end
    end

    context 'when restriction is NAMESPACE_LABEL_SELECTOR' do
      let(:restriction) do
        double('restriction', name: Authentication::AuthnK8s::Restrictions::NAMESPACE_LABEL_SELECTOR, value: 'env=production')
      end

      context 'and label selector is valid' do
        before do
          allow(k8s_resource_validator)
            .to receive(:valid_namespace?)
            .with(label_selector: 'env=production')
            .and_return(true)
        end

        it 'returns true' do
          expect(subject.valid_restriction?(restriction)).to be(true)
        end

        it 'calls validator with the label selector' do
          subject.valid_restriction?(restriction)
          expect(k8s_resource_validator).to have_received(:valid_namespace?).with(label_selector: 'env=production')
        end
      end

      context 'and label selector raises error' do
        before do
          allow(k8s_resource_validator)
            .to receive(:valid_namespace?)
            .with(label_selector: 'invalid')
            .and_raise(::Errors::Authentication::AuthnK8s::InvalidLabelSelector.new('invalid'))
        end

        let(:restriction) do
          double('restriction', name: Authentication::AuthnK8s::Restrictions::NAMESPACE_LABEL_SELECTOR, value: 'invalid')
        end

        it 'propagates the error' do
          expect do
            subject.valid_restriction?(restriction)
          end.to raise_error(
            ::Errors::Authentication::AuthnK8s::InvalidLabelSelector
          )
        end
      end
    end

    context 'when restriction is a resource type' do
      context 'with DEPLOYMENT restriction' do
        let(:restriction) do
          double('restriction', name: Authentication::AuthnK8s::Restrictions::DEPLOYMENT, value: 'my-deployment')
        end

        context 'and resource is valid' do
          before do
            allow(k8s_resource_validator)
              .to receive(:valid_resource?)
              .with(type: 'deployment', name: 'my-deployment')
              .and_return(true)
          end

          it 'returns true' do
            expect(subject.valid_restriction?(restriction)).to be(true)
          end

          it 'calls validator with underscore resource type' do
            subject.valid_restriction?(restriction)
            expect(k8s_resource_validator).to have_received(:valid_resource?).with(type: 'deployment', name: 'my-deployment')
          end
        end

        context 'and resource validation fails' do
          before do
            allow(k8s_resource_validator)
              .to receive(:valid_resource?)
              .with(type: 'deployment', name: 'my-deployment')
              .and_raise(::Errors::Authentication::AuthnK8s::K8sResourceNotFound.new('deployment', 'my-deployment', 'default'))
          end

          it 'propagates the error' do
            expect do
              subject.valid_restriction?(restriction)
            end.to raise_error(
              ::Errors::Authentication::AuthnK8s::K8sResourceNotFound
            )
          end
        end
      end

      context 'with STATEFUL_SET restriction' do
        let(:restriction) do
          double('restriction', name: Authentication::AuthnK8s::Restrictions::STATEFUL_SET, value: 'my-statefulset')
        end

        before do
          allow(k8s_resource_validator)
            .to receive(:valid_resource?)
            .with(type: 'stateful_set', name: 'my-statefulset')
            .and_return(true)
        end

        it 'converts stateful-set to stateful_set' do
          subject.valid_restriction?(restriction)
          expect(k8s_resource_validator).to have_received(:valid_resource?).with(type: 'stateful_set', name: 'my-statefulset')
        end

        it 'returns true' do
          expect(subject.valid_restriction?(restriction)).to be(true)
        end
      end

      context 'with DEPLOYMENT_CONFIG restriction' do
        let(:restriction) do
          double('restriction', name: Authentication::AuthnK8s::Restrictions::DEPLOYMENT_CONFIG, value: 'my-dc')
        end

        before do
          allow(k8s_resource_validator)
            .to receive(:valid_resource?)
            .with(type: 'deployment_config', name: 'my-dc')
            .and_return(true)
        end

        it 'converts deployment-config to deployment_config' do
          subject.valid_restriction?(restriction)
          expect(k8s_resource_validator).to have_received(:valid_resource?).with(type: 'deployment_config', name: 'my-dc')
        end

        it 'returns true' do
          expect(subject.valid_restriction?(restriction)).to be(true)
        end
      end

      context 'with SERVICE_ACCOUNT restriction' do
        let(:restriction) do
          double('restriction', name: Authentication::AuthnK8s::Restrictions::SERVICE_ACCOUNT, value: 'my-sa')
        end

        before do
          allow(k8s_resource_validator)
            .to receive(:valid_resource?)
            .with(type: 'service_account', name: 'my-sa')
            .and_return(true)
        end

        it 'converts service-account to service_account' do
          subject.valid_restriction?(restriction)
          expect(k8s_resource_validator).to have_received(:valid_resource?).with(type: 'service_account', name: 'my-sa')
        end

        it 'returns true' do
          expect(subject.valid_restriction?(restriction)).to be(true)
        end
      end

      context 'with POD restriction' do
        let(:restriction) do
          double('restriction', name: Authentication::AuthnK8s::Restrictions::POD, value: 'my-pod')
        end

        before do
          allow(k8s_resource_validator)
            .to receive(:valid_resource?)
            .with(type: 'pod', name: 'my-pod')
            .and_return(true)
        end

        it 'returns true without converting pod' do
          expect(subject.valid_restriction?(restriction)).to be(true)
          expect(k8s_resource_validator).to have_received(:valid_resource?).with(type: 'pod', name: 'my-pod')
        end
      end

      context 'with AUTHENTICATION_CONTAINER_NAME restriction' do
        let(:restriction) do
          double('restriction', name: Authentication::AuthnK8s::Restrictions::AUTHENTICATION_CONTAINER_NAME, value: 'my-container')
        end

        before do
          allow(k8s_resource_validator)
            .to receive(:valid_resource?)
            .with(type: 'authentication_container_name', name: 'my-container')
            .and_return(true)
        end

        it 'converts to authentication_container_name with underscore' do
          subject.valid_restriction?(restriction)
          expect(k8s_resource_validator).to have_received(:valid_resource?).with(type: 'authentication_container_name', name: 'my-container')
        end

        it 'returns true' do
          expect(subject.valid_restriction?(restriction)).to be(true)
        end
      end
    end
  end
end
