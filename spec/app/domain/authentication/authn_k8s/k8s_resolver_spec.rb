# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::K8sResolver) do
  describe '.for_resource' do
    context 'when resource type is known' do
      it 'returns the correct resolver class for deployment' do
        resolver_class = described_class.for_resource('deployment')
        expect(resolver_class).to eq(Authentication::AuthnK8s::K8sResolver::Deployment)
      end

      it 'returns the correct resolver class for deployment_config' do
        resolver_class = described_class.for_resource('deployment_config')
        expect(resolver_class).to eq(Authentication::AuthnK8s::K8sResolver::DeploymentConfig)
      end

      it 'returns the correct resolver class for replica_set' do
        resolver_class = described_class.for_resource('replica_set')
        expect(resolver_class).to eq(Authentication::AuthnK8s::K8sResolver::ReplicaSet)
      end

      it 'returns the correct resolver class for service_account' do
        resolver_class = described_class.for_resource('service_account')
        expect(resolver_class).to eq(Authentication::AuthnK8s::K8sResolver::ServiceAccount)
      end

      it 'returns the correct resolver class for stateful_set' do
        resolver_class = described_class.for_resource('stateful_set')
        expect(resolver_class).to eq(Authentication::AuthnK8s::K8sResolver::StatefulSet)
      end

      it 'returns the correct resolver class for pod' do
        resolver_class = described_class.for_resource('pod')
        expect(resolver_class).to eq(Authentication::AuthnK8s::K8sResolver::Pod)
      end
    end

    context 'when resource type is unknown' do
      it 'raises UnknownK8sResourceType error' do
        expect do
          described_class.for_resource('unknown_type')
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::UnknownK8sResourceType
        )
      end
    end
  end

  describe 'Base resolver properties' do
    let(:pod) do
      double(
        'pod',
        metadata: double(
          'metadata',
          name: 'test-pod',
          namespace: 'test-namespace',
          ownerReferences: []
        )
      )
    end

    let(:resource) do
      double(
        'resource',
        metadata: double(
          'metadata',
          name: 'test-resource',
          namespace: 'test-namespace'
        )
      )
    end

    let(:k8s_object_lookup) { double('k8s_object_lookup') }

    let(:resolver) do
      Authentication::AuthnK8s::K8sResolver::Pod.new(resource, pod, k8s_object_lookup)
    end

    describe '#name' do
      it 'returns the resource name' do
        expect(resolver.name).to eq('test-resource')
      end
    end

    describe '#namespace' do
      it 'returns the resource namespace' do
        expect(resolver.namespace).to eq('test-namespace')
      end
    end

    describe '#pod_name' do
      it 'returns the pod name as a quoted string' do
        expect(resolver.pod_name).to eq('"test-pod"')
      end
    end

    describe '#pod_owner_refs' do
      it 'returns the pod owner references' do
        owner_refs = [double('owner_ref')]
        allow(pod.metadata).to receive(:ownerReferences).and_return(owner_refs)
        expect(resolver.pod_owner_refs).to eq(owner_refs)
      end

      it 'returns nil when no owner references' do
        allow(pod.metadata).to receive(:ownerReferences).and_return(nil)
        expect(resolver.pod_owner_refs).to be_nil
      end
    end
  end

  describe 'Deployment resolver' do
    let(:pod) do
      double(
        'pod',
        metadata: double(
          'metadata',
          name: 'myapp-deployment-abc123',
          namespace: 'default',
          ownerReferences: pod_owner_refs
        )
      )
    end

    let(:resource) do
      double(
        'resource',
        metadata: double(
          'metadata',
          name: 'myapp-deployment',
          namespace: 'default'
        )
      )
    end

    let(:k8s_object_lookup) { double('k8s_object_lookup') }

    let(:resolver) do
      Authentication::AuthnK8s::K8sResolver::Deployment.new(resource, pod, k8s_object_lookup)
    end

    context 'when pod is properly managed by a deployment' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicaSet', name: 'myapp-deployment-replicaset')
        ]
      end

      let(:replica_set) do
        double(
          'replica_set',
          metadata: double(
            'metadata',
            ownerReferences: [
              double('deployment_ref', kind: 'Deployment', name: 'myapp-deployment')
            ]
          )
        )
      end

      let(:deployment) do
        double(
          'deployment',
          metadata: double('metadata', name: 'myapp-deployment')
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replica_set', 'myapp-deployment-replicaset', 'default')
          .and_return(replica_set)

        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('deployment', 'myapp-deployment', 'default')
          .and_return(deployment)
      end

      it 'validates successfully' do
        expect { resolver.validate_pod }.not_to raise_error
      end
    end

    context 'when pod is missing ReplicaSet owner reference' do
      let(:pod_owner_refs) { [] }

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end

    context 'when pod has ReplicaSet ref but ReplicaSet is missing Deployment' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicaSet', name: 'myapp-deployment-replicaset')
        ]
      end

      let(:replica_set) do
        double(
          'replica_set',
          metadata: double('metadata', ownerReferences: [])
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replica_set', 'myapp-deployment-replicaset', 'default')
          .and_return(replica_set)
      end

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end

    context 'when deployment name does not match' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicaSet', name: 'myapp-deployment-replicaset')
        ]
      end

      let(:replica_set) do
        double(
          'replica_set',
          metadata: double(
            'metadata',
            ownerReferences: [
              double('deployment_ref', kind: 'Deployment', name: 'different-deployment')
            ]
          )
        )
      end

      let(:deployment) do
        double(
          'deployment',
          metadata: double('metadata', name: 'different-deployment')
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replica_set', 'myapp-deployment-replicaset', 'default')
          .and_return(replica_set)

        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('deployment', 'different-deployment', 'default')
          .and_return(deployment)
      end

      it 'raises PodRelationMismatchError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodRelationMismatchError
        )
      end
    end

    context 'when pod has non-ReplicaSet owner references' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'StatefulSet', name: 'some-statefulset')
        ]
      end

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end

    context 'when pod owner references is nil' do
      let(:pod_owner_refs) { nil }

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end

    context 'when replica set owner references is nil' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicaSet', name: 'myapp-deployment-replicaset')
        ]
      end

      let(:replica_set) do
        double(
          'replica_set',
          metadata: double('metadata', ownerReferences: nil)
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replica_set', 'myapp-deployment-replicaset', 'default')
          .and_return(replica_set)
      end

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end
  end

  describe 'DeploymentConfig resolver' do
    let(:pod) do
      double(
        'pod',
        metadata: double(
          'metadata',
          name: 'myapp-deploymentconfig-abc123',
          namespace: 'openshift-namespace',
          ownerReferences: pod_owner_refs
        )
      )
    end

    let(:resource) do
      double(
        'resource',
        metadata: double(
          'metadata',
          name: 'myapp-deploymentconfig',
          namespace: 'openshift-namespace'
        )
      )
    end

    let(:k8s_object_lookup) { double('k8s_object_lookup') }

    let(:resolver) do
      Authentication::AuthnK8s::K8sResolver::DeploymentConfig.new(resource, pod, k8s_object_lookup)
    end

    context 'when pod is properly managed by a deployment config' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicationController', name: 'myapp-deploymentconfig-rc')
        ]
      end

      let(:replication_controller) do
        double(
          'replication_controller',
          metadata: double(
            'metadata',
            ownerReferences: [
              double('dc_ref', kind: 'DeploymentConfig', name: 'myapp-deploymentconfig')
            ]
          )
        )
      end

      let(:deployment_config) do
        double(
          'deployment_config',
          metadata: double('metadata', name: 'myapp-deploymentconfig')
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replication_controller', 'myapp-deploymentconfig-rc', 'openshift-namespace')
          .and_return(replication_controller)

        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('deployment_config', 'myapp-deploymentconfig', 'openshift-namespace')
          .and_return(deployment_config)
      end

      it 'validates successfully' do
        expect { resolver.validate_pod }.not_to raise_error
      end
    end

    context 'when pod is missing ReplicationController owner reference' do
      let(:pod_owner_refs) { [] }

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end

    context 'when ReplicationController is missing DeploymentConfig' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicationController', name: 'myapp-deploymentconfig-rc')
        ]
      end

      let(:replication_controller) do
        double(
          'replication_controller',
          metadata: double('metadata', ownerReferences: [])
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replication_controller', 'myapp-deploymentconfig-rc', 'openshift-namespace')
          .and_return(replication_controller)
      end

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end

    context 'when deployment config name does not match' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicationController', name: 'myapp-deploymentconfig-rc')
        ]
      end

      let(:replication_controller) do
        double(
          'replication_controller',
          metadata: double(
            'metadata',
            ownerReferences: [
              double('dc_ref', kind: 'DeploymentConfig', name: 'different-dc')
            ]
          )
        )
      end

      let(:deployment_config) do
        double(
          'deployment_config',
          metadata: double('metadata', name: 'different-dc')
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replication_controller', 'myapp-deploymentconfig-rc', 'openshift-namespace')
          .and_return(replication_controller)

        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('deployment_config', 'different-dc', 'openshift-namespace')
          .and_return(deployment_config)
      end

      it 'raises PodRelationMismatchError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodRelationMismatchError
        )
      end
    end

    context 'when pod owner references is nil' do
      let(:pod_owner_refs) { nil }

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end

    context 'when replication controller owner references is nil' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicationController', name: 'myapp-deploymentconfig-rc')
        ]
      end

      let(:replication_controller) do
        double(
          'replication_controller',
          metadata: double('metadata', ownerReferences: nil)
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replication_controller', 'myapp-deploymentconfig-rc', 'openshift-namespace')
          .and_return(replication_controller)
      end

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end
  end

  describe 'ReplicaSet resolver' do
    let(:pod) do
      double(
        'pod',
        metadata: double(
          'metadata',
          name: 'test-replicaset-pod-123',
          namespace: 'default',
          ownerReferences: pod_owner_refs
        )
      )
    end

    let(:resource) do
      double(
        'resource',
        metadata: double(
          'metadata',
          name: 'test-replicaset',
          namespace: 'default'
        )
      )
    end

    let(:k8s_object_lookup) { double('k8s_object_lookup') }

    let(:resolver) do
      Authentication::AuthnK8s::K8sResolver::ReplicaSet.new(resource, pod, k8s_object_lookup)
    end

    context 'when pod is directly managed by the replica set' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicaSet', name: 'test-replicaset')
        ]
      end

      let(:replica_set) do
        double(
          'replica_set',
          metadata: double(
            'metadata',
            name: 'test-replicaset'
          )
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replica_set', 'test-replicaset', 'default')
          .and_return(replica_set)
      end

      it 'validates successfully' do
        expect { resolver.validate_pod }.not_to raise_error
      end
    end

    context 'when pod is missing ReplicaSet owner reference' do
      let(:pod_owner_refs) { [] }

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end

    context 'when replica set name does not match' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'ReplicaSet', name: 'different-replicaset')
        ]
      end

      let(:replica_set) do
        double(
          'replica_set',
          metadata: double(
            'metadata',
            name: 'different-replicaset'
          )
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('replica_set', 'different-replicaset', 'default')
          .and_return(replica_set)
      end

      it 'raises PodRelationMismatchError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodRelationMismatchError
        )
      end
    end

    context 'when pod owner references is nil' do
      let(:pod_owner_refs) { nil }

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end
  end

  describe 'ServiceAccount resolver' do
    let(:pod) do
      double(
        'pod',
        metadata: double(
          'metadata',
          name: 'test-pod',
          namespace: 'default'
        ),
        spec: double(
          'spec',
          serviceAccountName: service_account_name
        )
      )
    end

    let(:resource) do
      double(
        'resource',
        metadata: double(
          'metadata',
          name: 'test-service-account',
          namespace: 'default'
        )
      )
    end

    let(:k8s_object_lookup) { double('k8s_object_lookup') }

    let(:resolver) do
      Authentication::AuthnK8s::K8sResolver::ServiceAccount.new(resource, pod, k8s_object_lookup)
    end

    context 'when pod service account matches resource name' do
      let(:service_account_name) { 'test-service-account' }

      it 'validates successfully' do
        expect { resolver.validate_pod }.not_to raise_error
      end
    end

    context 'when pod service account does not match resource name' do
      let(:service_account_name) { 'different-service-account' }

      it 'raises PodRelationMismatchError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodRelationMismatchError
        )
      end
    end
  end

  describe 'StatefulSet resolver' do
    let(:pod) do
      double(
        'pod',
        metadata: double(
          'metadata',
          name: 'test-statefulset-0',
          namespace: 'default',
          ownerReferences: pod_owner_refs
        )
      )
    end

    let(:resource) do
      double(
        'resource',
        metadata: double(
          'metadata',
          name: 'test-statefulset',
          namespace: 'default'
        )
      )
    end

    let(:k8s_object_lookup) { double('k8s_object_lookup') }

    let(:resolver) do
      Authentication::AuthnK8s::K8sResolver::StatefulSet.new(resource, pod, k8s_object_lookup)
    end

    context 'when pod is directly managed by the stateful set' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'StatefulSet', name: 'test-statefulset')
        ]
      end

      let(:stateful_set) do
        double(
          'stateful_set',
          metadata: double(
            'metadata',
            name: 'test-statefulset'
          )
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('stateful_set', 'test-statefulset', 'default')
          .and_return(stateful_set)
      end

      it 'validates successfully' do
        expect { resolver.validate_pod }.not_to raise_error
      end
    end

    context 'when pod is missing StatefulSet owner reference' do
      let(:pod_owner_refs) { [] }

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end

    context 'when stateful set name does not match' do
      let(:pod_owner_refs) do
        [
          double('owner_ref', kind: 'StatefulSet', name: 'different-statefulset')
        ]
      end

      let(:stateful_set) do
        double(
          'stateful_set',
          metadata: double(
            'metadata',
            name: 'different-statefulset'
          )
        )
      end

      before do
        allow(k8s_object_lookup)
          .to receive(:find_object_by_name)
          .with('stateful_set', 'different-statefulset', 'default')
          .and_return(stateful_set)
      end

      it 'raises PodRelationMismatchError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodRelationMismatchError
        )
      end
    end

    context 'when pod owner references is nil' do
      let(:pod_owner_refs) { nil }

      it 'raises PodMissingRelationError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodMissingRelationError
        )
      end
    end
  end

  describe 'Pod resolver' do
    let(:pod) do
      double(
        'pod',
        metadata: double(
          'metadata',
          name: pod_name,
          namespace: 'default'
        )
      )
    end

    let(:resource) do
      double(
        'resource',
        metadata: double(
          'metadata',
          name: resource_name,
          namespace: 'default'
        )
      )
    end

    let(:k8s_object_lookup) { double('k8s_object_lookup') }

    let(:resolver) do
      Authentication::AuthnK8s::K8sResolver::Pod.new(resource, pod, k8s_object_lookup)
    end

    context 'when pod name matches resource name' do
      let(:pod_name) { 'my-pod' }
      let(:resource_name) { 'my-pod' }

      it 'validates successfully' do
        expect { resolver.validate_pod }.not_to raise_error
      end
    end

    context 'when pod name does not match resource name' do
      let(:pod_name) { 'pod-one' }
      let(:resource_name) { 'pod-two' }

      it 'raises PodNameMismatchError' do
        expect do
          resolver.validate_pod
        end.to raise_error(
          ::Errors::Authentication::AuthnK8s::PodNameMismatchError
        )
      end
    end
  end
end
