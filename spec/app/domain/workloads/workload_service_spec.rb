# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::WorkloadService do
  let(:auth_service) { instance_double(Authorisation::AuthorisationService) }
  let(:authn_descriptor_service) { instance_double(Workloads::AuthnDescriptorService) }
  let(:annotation_service) { instance_double(Annotations::AnnotationService) }
  let(:owner_service) { instance_double(Branches::OwnerService) }
  let(:res_service) { instance_double(Resources::ResourceService) }
  let(:membership_service) { instance_double(Memberships::MembershipService) }
  let(:role_repo) { class_double('Role') }
  let(:config) { instance_double('Config', max_restricted_to: 5, conjur_restricted_ip_enabled: true) }
  let(:logger) { instance_double('Logger', debug?: false, debug: nil, error: nil) }

  let(:service) do
    described_class.send(:new,
                         auth_service: auth_service,
                         authn_descriptor_service: authn_descriptor_service,
                         annotation_service: annotation_service,
                         owner_service: owner_service,
                         res_service: res_service,
                         membership_service: membership_service,
                         role_repo: role_repo,
                         config: config,
                         logger: logger)
  end

  let(:role) { instance_double('Role', id: 'role-id') }
  let(:account) { 'test-account' }
  let(:owner_id) { 'test-account:user:owner' }

  let(:descriptor) { Workloads::AuthnDescriptor.new(type: 'api_key') }

  let(:workload) do
    instance_double(
      Workloads::Workload,
      name: 'wl',
      branch: 'br',
      type: 'jenkins',
      subtype: '',
      owner: instance_double('Owner'),
      authn_descriptors: [descriptor],
      annotations: { 'foo' => 'bar' },
      restricted_to: ['1.2.3.4/32'],
      kube_type?: false,
      identifier: 'br/wl'
    )
  end

  let(:host_id) { 'test-account:host:br/wl' }
  let(:policy_id) { 'test-account:policy:br' }

  let(:host_role) do
    instance_double('HostRole',
                    api_key: 'generated-api-key',
                    restricted_to: [IPAddr.new('1.2.3.4/32')],
                    save: true).tap do |r|
      allow(r).to receive(:restricted_to=)
    end
  end

  let(:host_res) do
    instance_double('Resource',
                    annotations: [
                      instance_double('Annotation', name: 'type', value: 'jenkins'),
                      instance_double('Annotation', name: 'subtype', value: ''),
                      instance_double('Annotation', name: 'foo', value: 'bar')
                    ],
                    account: account,
                    id: host_id,
                    identifier: workload.identifier,
                    owner_id: owner_id,
                    role: host_role)
  end

  before do
    allow(owner_service).to receive(:resource_owner_id).and_return(owner_id)
    allow(res_service).to receive(:save_res).and_return(host_res)
    allow(res_service).to receive(:read_res).and_return(host_res)
    allow(role_repo).to receive(:create).and_return(host_role)
    allow(annotation_service).to receive(:create_annotation)
    allow(authn_descriptor_service).to receive(:add_descriptor_to_authenticators_group)
    allow(authn_descriptor_service).to receive(:collect_authn_descriptors_annotations).and_return('authn/api-key' => 'true')
    allow(authn_descriptor_service).to receive(:regain_authn_desc_views).and_return([{ 'type' => 'api_key', 'data' => {} }])
    allow(Branches::Owner).to receive(:h_from_model_id).and_return(kind: 'user', id: 'owner')
    allow(Sequel).to receive(:pg_array).and_return(['1.2.3.4/32'])
  end

  describe '#create_workload' do
    it 'creates workload and returns serialized view' do
      result = service.create_workload(role, account, workload)

      expect(result['name']).to eq('wl')
      expect(result['branch']).to eq('br')
      expect(result['owner']).to eq('kind' => 'user', 'id' => 'owner')
      expect(result['authn_descriptors']).to eq([{ 'type' => 'api_key', 'data' => {} }])
    end

    it 'creates annotations from workload and authn descriptors' do
      service.create_workload(role, account, workload)

      expect(annotation_service).to have_received(:create_annotation).with(host_id, 'foo', 'bar', policy_id)
      expect(annotation_service).to have_received(:create_annotation).with(host_id, 'authn/api-key', 'true', policy_id)
      expect(annotation_service).to have_received(:create_annotation).with(host_id, 'type', 'jenkins', policy_id)
    end

    it 'adds each descriptor to authenticators groups' do
      service.create_workload(role, account, workload)

      expect(authn_descriptor_service).to have_received(:add_descriptor_to_authenticators_group)
        .with(role, account, host_res, descriptor)
    end
  end

  describe '#read_workload' do
    let(:workload_show) { instance_double(Workloads::WorkloadShow, identifier: 'br/wl') }

    it 'returns workload view for readable host' do
      result = service.read_workload(role, account, workload_show)

      expect(result[:name]).to eq('wl')
      expect(result[:branch]).to eq('br')
      expect(result[:type]).to eq('jenkins')
      expect(result[:owner]).to eq(kind: 'user', id: 'owner')
    end
  end

  describe '#save_restricted_to' do
    it 'persists restricted_to as pg_array' do
      service.send(:save_restricted_to, host_role, ['1.2.3.4/32'])

      expect(host_role).to have_received(:restricted_to=).with(['1.2.3.4/32'])
      expect(host_role).to have_received(:save)
    end

    it 'raises when restricted_to exceeds configured limit' do
      expect do
        service.send(:save_restricted_to, host_role, Array.new(6, '1.2.3.4/32'))
      end.to raise_error(ApplicationController::UnprocessableContent, /Too many CIDR entries/)
    end
  end

  describe '#delete_workload' do
    let(:branch_identifier) { 'data/branch' }
    let(:workload_name) { 'wl' }
    let(:workload_identifier) { 'data/branch/wl' }
    let(:workload_host_id) { 'test-account:host:data/branch/wl' }
    let(:workload_resource) { instance_double('Resource', resource_id: workload_host_id, destroy: true) }
    let(:workload_role) { instance_double('RoleRecord', destroy: true) }

    before do
      allow(res_service).to receive(:check_exists).with(account, 'host', workload_identifier)
      allow(res_service).to receive(:find_owned_resources).with(workload_host_id).and_return([])
      allow(res_service).to receive(:fetch_by_id).with(workload_host_id).and_return(workload_resource)
      allow(role_repo).to receive(:[]).with(workload_host_id).and_return(workload_role)
      allow(role).to receive(:allowed_to?).with(:update, workload_resource).and_return(true)
    end

    it 'deletes workload resource and its role' do
      service.delete_workload(role, account, branch_identifier, workload_name)

      expect(workload_resource).to have_received(:destroy)
      expect(workload_role).to have_received(:destroy)
    end

    it 'raises forbidden when caller has no update permission' do
      allow(role).to receive(:allowed_to?).with(:update, workload_resource).and_return(false)

      expect do
        service.delete_workload(role, account, branch_identifier, workload_name)
      end.to raise_error(Exceptions::Forbidden, /Insufficient permissions/)
    end
  end
end

