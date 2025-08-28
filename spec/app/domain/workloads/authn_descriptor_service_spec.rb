# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::AuthnDescriptorService do
  let(:annotation_service) { instance_double(Annotations::AnnotationService) }
  let(:res_service) { instance_double(Resources::ResourceService) }
  let(:membership_service) { instance_double(Memberships::MembershipService) }
  let(:branch_service) { instance_double(Branches::BranchService) }
  let(:logger) { double('Logger', debug: nil) }
  let(:service) do
    described_class.send(:new,
                         annotation_service: annotation_service,
                         res_service: res_service,
                         membership_service: membership_service,
                         branch_service: branch_service,
                         logger: logger
    )
  end

  let(:role) { double('Role') }
  let(:account) { 'test-account' }
  let(:member_res) { double('MemberRes') }
  let(:host_role) { double('HostRole', api_key: 'api-key-value') }
  let(:api_key_descriptor) { double('AuthnDescriptor', api_key?: true, as_json: { 'type' => 'api_key' }) }
  let(:cert_descriptor) do
    double('AuthnDescriptor',
           api_key?: false,
           type: 'cert',
           service_id: 'svc',
           as_json: { 'type' => 'cert', 'service_id' => 'svc', 'data' => { 'cn' => 'foo' } },
           data: { 'cn' => 'foo' },
           type?: false
    )
  end

  describe '#add_descriptor_to_authenticators_group' do
    it 'returns immediately for api_key descriptors' do
      expect(service.add_descriptor_to_authenticators_group(role, account, member_res, api_key_descriptor)).to be_nil
    end

    it 'adds non-api_key descriptor to group' do
      allow(cert_descriptor).to receive(:type).and_return('cert')
      allow(cert_descriptor).to receive(:service_id).and_return('svc')
      allow(cert_descriptor).to receive(:api_key?).and_return(false)
      allow(branch_service).to receive(:read_and_auth_branch)
      allow(res_service).to receive(:get_res).and_return('group_res')
      allow(membership_service).to receive(:check_membership_not_exist)
      allow(membership_service).to receive(:create_membership_db)

      expect {
        service.add_descriptor_to_authenticators_group(role, account, member_res, cert_descriptor)
      }.not_to raise_error
    end
  end

  describe '#format_authn_descriptors' do
    it 'enhances api_key descriptor with api key' do
      result = service.format_authn_descriptors(host_role, [api_key_descriptor])
      expect(result.first['data']['value']).to eq('api-key-value')
    end

    it 'returns as_json for non-api_key descriptors' do
      allow(cert_descriptor).to receive(:api_key?).and_return(false)
      result = service.format_authn_descriptors(host_role, [cert_descriptor])
      expect(result.first['type']).to eq('cert')
    end
  end

  describe '#collect_authn_descriptors_annotations' do
    it 'returns annotation for api_key' do
      result = service.collect_authn_descriptors_annotations([api_key_descriptor])
      expect(result).to include('authn/api-key' => 'true')
    end

    it 'returns annotation for cert descriptor' do
      allow(cert_descriptor).to receive(:type?).with('cert').and_return(true)
      allow(cert_descriptor).to receive(:type?).with('jwt').and_return(false)
      result = service.collect_authn_descriptors_annotations([cert_descriptor])
      expect(result.keys.any? { |k| k.include?('authn-cert') }).to be true
    end
  end
end
