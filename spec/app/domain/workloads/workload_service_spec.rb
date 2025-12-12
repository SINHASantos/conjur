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
      }.to raise_error(ApplicationController::UnprocessableEntity)
    end
  end
end
