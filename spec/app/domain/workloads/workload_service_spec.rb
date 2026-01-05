# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::WorkloadService do
  let(:authn_descriptor_service) { instance_double(Workloads::AuthnDescriptorService) }
  let(:annotation_service) { instance_double(Annotations::AnnotationService) }
  let(:owner_service) { instance_double(Branches::OwnerService) }
  let(:res_service) { instance_double(Resources::ResourceService) }
  let(:role_repo) { class_double('Role') }
  let(:config) { double('Config', max_restricted_to: 5) }
  let(:logger) { double('Logger', debug: nil, debug?: false) }
  let(:service) do
    described_class.send(:new,
                         authn_descriptor_service: authn_descriptor_service,
                         annotation_service: annotation_service,
                         owner_service: owner_service,
                         res_service: res_service,
                         role_repo: role_repo,
                         config: config,
                         logger: logger)
  end

  let(:role) { double('Role', id: 'role-id') }
  let(:account) { 'test-account' }
  let(:workload) do
    instance_double(
      Workloads::Workload,
      name: 'wl',
      branch: 'br',
      type: 'jenkins',
      subtype: '',
      owner: double('Owner'),
      authn_descriptors: [double('AuthnDescriptor')],
      annotations: { 'foo' => 'bar' },
      restricted_to: ['1.2.3.4/32'],
      as_json: { 'name' => 'wl', 'branch' => 'br', 'type' => 'jenkins', 'subtype' => '' },
      kube_type?: false,
      identifier: 'br/wl'
    )
  end

  let(:policy_id) { 'test-account:policy:br' }
  let(:host_id) { 'test-account:host:br/wl' }
  let(:owner_id) { 'test-account:user:owner' }
  let(:host_res) { double('HostRes') }
  let(:host_role) { double('HostRole', api_key: 'api-key', restricted_to: nil, save: true).as_null_object }

  before do
    allow(service).to receive(:full_id).and_call_original
    allow(service).to receive(:to_identifier).and_call_original
    allow(owner_service).to receive(:resource_owner_id).and_return(owner_id)
    allow(res_service).to receive(:save_res).and_return(host_res)
    allow(role_repo).to receive(:create).and_return(host_role)
    allow(annotation_service).to receive(:create_annotation)
    allow(authn_descriptor_service).to receive(:add_descriptor_to_authenticators_group)
    allow(authn_descriptor_service).to receive(:format_authn_descriptors).and_return([{ 'type' => 'api_key' }])
    allow(authn_descriptor_service).to receive(:collect_authn_descriptors_annotations).and_return({ 'authn/api-key' => 'true' })
  end

  describe '#create_workload' do
    it 'creates workload and returns as_json with owner and authn_descriptors' do
      result = service.create_workload(role, account, workload)
      expect(result).to include(:authn_descriptors)
      expect(result[:authn_descriptors]).to eq([{ 'type' => 'api_key' }])
    end

    it 'calls annotation_service for each annotation' do
      expect(annotation_service).to receive(:create_annotation).at_least(:once)
      service.create_workload(role, account, workload)
    end

    it 'calls add_descriptor_to_authenticators_group for each descriptor' do
      expect(authn_descriptor_service).to receive(:add_descriptor_to_authenticators_group).at_least(:once)
      service.create_workload(role, account, workload)
    end
  end

  describe '#save_restricted_to' do
    it 'sets restricted_to on host_role' do
      arr = ['1.2.3.4/32']
      expect(host_role).to receive(:restricted_to=).with(instance_of(Sequel::Postgres::PGArray))
      expect(host_role).to receive(:save)
      service.send(:save_restricted_to, host_role, arr)
    end

    it 'raises error if too many CIDRs' do
      arr = Array.new(6, '1.2.3.4/32')
      expect {
        service.send(:save_restricted_to, host_role, arr)
      }.to raise_error(ApplicationController::UnprocessableContent)
    end
  end

  describe '#delete_workload' do
    let(:branch_identifier) { 'data/branch' }
    let(:workload_name) { 'test-workload' }
    let(:identifier) { "#{branch_identifier}/#{workload_name}" }
    let(:workload_host_id) { "#{account}:host:#{identifier}" }
    let(:workload_resource) { double('WorkloadResource', resource_id: workload_host_id, owner_id: owner_id) }
    let(:workload_role) { double('WorkloadRole', role_id: workload_host_id) }

    before do
      allow(res_service).to receive(:get_res).with(account, 'host', identifier).and_return(workload_resource)
      allow(res_service).to receive(:fetch_by_id).with(workload_host_id).and_return(workload_resource)
      allow(role_repo).to receive(:[]).with(workload_host_id).and_return(workload_role)
      allow(res_service).to receive(:find_owned_resources).and_return([])
      allow(workload_resource).to receive(:destroy)
      allow(workload_role).to receive(:destroy)
    end

    context 'when workload exists' do
      before do
        allow(role).to receive(:allowed_to?).with(:update, workload_resource).and_return(true)
      end

      it 'deletes the workload successfully' do

        expect(res_service).to receive(:get_res).with(account, 'host', identifier)
        expect(workload_resource).to receive(:destroy)
        expect(workload_role).to receive(:destroy)

        result = service.delete_workload(role, account, branch_identifier, workload_name)
        expect(result).to be_nil
      end

    end

    context 'when workload does not exist' do
      it 'raises RecordNotFound' do

        # get_res raises RecordNotFound when resource doesn't exist (not returns nil)
        allow(res_service).to receive(:get_res).and_raise(Exceptions::RecordNotFound, workload_host_id)

        expect {
          service.delete_workload(role, account, branch_identifier, workload_name)
        }.to raise_error(Exceptions::RecordNotFound)
      end
    end

    context 'when workload has owned resources' do
      let(:owned_resource_id) { "#{account}:host:data/owned-resource" }
      let(:owned_resource) { double('OwnedResource', resource_id: owned_resource_id, owner_id: workload_host_id) }
      let(:owned_role) { double('OwnedRole', role_id: owned_resource_id) }

      before do
        allow(role_repo).to receive(:[]).with(owned_resource_id).and_return(owned_role)
        allow(res_service).to receive(:fetch_by_id).with(owned_resource_id).and_return(owned_resource)
        allow(owned_resource).to receive(:destroy)
        allow(owned_role).to receive(:destroy)
        allow(role).to receive(:allowed_to?).with(:update, workload_resource).and_return(true)
        allow(role).to receive(:allowed_to?).with(:update, owned_resource).and_return(true)
      end

      it 'recursively deletes owned resources' do
        # Mock owned resources query
        allow(res_service).to receive(:find_owned_resources).with(workload_host_id).and_return([owned_resource])
        allow(res_service).to receive(:find_owned_resources).with(owned_resource_id).and_return([])

        expect(owned_resource).to receive(:destroy)
        expect(owned_role).to receive(:destroy)
        expect(workload_resource).to receive(:destroy)
        expect(workload_role).to receive(:destroy)

        service.delete_workload(role, account, branch_identifier, workload_name)
      end
    end

    context 'Role permission checks' do
      let(:user_with_permission) { double('UserWithPermission', id: 'test-account:user:authorized', role_id: 'test-account:user:authorized') }
      let(:user_without_permission) { double('UserWithoutPermission', id: 'test-account:user:unauthorized', role_id: 'test-account:user:unauthorized') }

      before do
        allow(res_service).to receive(:find_owned_resources).and_return([])
      end

      it 'allows deletion when user has update permission' do
        allow(user_with_permission).to receive(:allowed_to?).with(:update, workload_resource).and_return(true)

        expect {
          service.delete_workload(user_with_permission, account, branch_identifier, workload_name)
        }.not_to raise_error
      end

      it 'prevents deletion when user lacks update permission' do
        allow(user_without_permission).to receive(:allowed_to?).with(:update, workload_resource).and_return(false)

        expect {
          service.delete_workload(user_without_permission, account, branch_identifier, workload_name)
        }.to raise_error(Exceptions::Forbidden, /Insufficient permissions to delete resource/)
      end

      it 'checks update permission on owned resources' do
        owned_resource_id = "#{account}:host:data/owned-resource"
        owned_resource = double('OwnedResource', resource_id: owned_resource_id, owner_id: workload_host_id)
        owned_role = double('OwnedRole', role_id: owned_resource_id)

        allow(res_service).to receive(:fetch_by_id).with(owned_resource_id).and_return(owned_resource)
        allow(role_repo).to receive(:[]).with(owned_resource_id).and_return(owned_role)
        allow(owned_resource).to receive(:destroy)
        allow(owned_role).to receive(:destroy)

        allow(res_service).to receive(:find_owned_resources).with(workload_host_id).and_return([owned_resource])
        allow(res_service).to receive(:find_owned_resources).with(owned_resource_id).and_return([])

        allow(user_with_permission).to receive(:allowed_to?).with(:update, workload_resource).and_return(true)
        allow(user_with_permission).to receive(:allowed_to?).with(:update, owned_resource).and_return(false)

        expect {
          service.delete_workload(user_with_permission, account, branch_identifier, workload_name)
        }.to raise_error(Exceptions::Forbidden, /Insufficient permissions to delete resource/)
      end
    end

    context 'error handling' do
      before do
        allow(res_service).to receive(:find_owned_resources).and_return([])
        allow(role).to receive(:allowed_to?).with(:update, workload_resource).and_return(true)
      end

      it 'raises Forbidden on ForeignKeyConstraintViolation' do
        allow(workload_resource).to receive(:destroy).and_raise(Sequel::ForeignKeyConstraintViolation)

        expect {
          service.delete_workload(role, account, branch_identifier, workload_name)
        }.to raise_error(Exceptions::Forbidden, /existing dependencies/)
      end

      it 'does not catch other exceptions' do
        allow(workload_resource).to receive(:destroy).and_raise(StandardError.new('Unexpected error'))

        expect {
          service.delete_workload(role, account, branch_identifier, workload_name)
        }.to raise_error(StandardError, 'Unexpected error')
      end
    end
  end

  describe '#delete_resource_recursively!' do
    let(:resource_id) { 'test-account:host:data/resource' }
    let(:resource_obj) { double('Resource', resource_id: resource_id, owner_id: 'test-account:policy:data') }
    let(:role_obj) { double('Role', role_id: resource_id) }
    let(:visited) { Set.new }

    before do
      allow(res_service).to receive(:fetch_by_id).with(resource_id).and_return(resource_obj)
      allow(role_repo).to receive(:[]).with(resource_id).and_return(role_obj)
      allow(res_service).to receive(:find_owned_resources).and_return([])
      allow(resource_obj).to receive(:destroy)
      allow(role_obj).to receive(:destroy)
      allow(role).to receive(:allowed_to?).with(:update, resource_obj).and_return(true)
    end

    it 'prevents infinite recursion with circular ownership' do
      # Add resource to visited set
      visited.add(resource_id)

      expect(resource_obj).not_to receive(:destroy)
      expect(role_obj).not_to receive(:destroy)

      service.send(:delete_resource_recursively!, resource_id, role, visited)
    end

    it 'deletes resource and associated role' do
      expect(resource_obj).to receive(:destroy)
      expect(role_obj).to receive(:destroy)

      service.send(:delete_resource_recursively!, resource_id, role, visited)
    end

    it 'adds resource to visited set' do
      expect(visited).not_to include(resource_id)

      service.send(:delete_resource_recursively!, resource_id, role, visited)

      expect(visited).to include(resource_id)
    end

    it 'checks role permission before deleting' do
      expect(role).to receive(:allowed_to?).with(:update, resource_obj).and_return(true)

      service.send(:delete_resource_recursively!, resource_id, role, visited)
    end

    it 'raises Forbidden when user lacks update permission' do
      allow(role).to receive(:allowed_to?).with(:update, resource_obj).and_return(false)

      expect {
        service.send(:delete_resource_recursively!, resource_id, role, visited)
      }.to raise_error(Exceptions::Forbidden, /Insufficient permissions/)
    end

    it 'handles missing resource gracefully' do
      allow(res_service).to receive(:fetch_by_id).with(resource_id).and_return(nil)

      expect {
        service.send(:delete_resource_recursively!, resource_id, role, visited)
      }.not_to raise_error
    end

    it 'handles missing role gracefully' do
      allow(role_repo).to receive(:[]).with(resource_id).and_return(nil)

      expect {
        service.send(:delete_resource_recursively!, resource_id, role, visited)
      }.not_to raise_error
    end
  end

  describe '#check_update_permission!' do
    let(:resource_id) { 'test-account:host:data/resource' }
    let(:resource_obj) { double('Resource', resource_id: resource_id) }
    let(:user_role) { double('UserRole', role_id: 'test-account:user:testuser') }

    before do
      allow(res_service).to receive(:fetch_by_id).with(resource_id).and_return(resource_obj)
    end

    it 'does not raise error when user has update permission' do
      allow(user_role).to receive(:allowed_to?).with(:update, resource_obj).and_return(true)

      expect {
        service.send(:check_update_permission!, resource_id, user_role)
      }.not_to raise_error
    end

    it 'raises Forbidden when user lacks update permission' do
      allow(user_role).to receive(:allowed_to?).with(:update, resource_obj).and_return(false)

      expect {
        service.send(:check_update_permission!, resource_id, user_role)
      }.to raise_error(Exceptions::Forbidden, /Insufficient permissions to delete resource/)
    end

    it 'does not raise error when resource does not exist' do
      allow(res_service).to receive(:fetch_by_id).with(resource_id).and_return(nil)

      expect {
        service.send(:check_update_permission!, resource_id, user_role)
      }.not_to raise_error
    end
  end
end
