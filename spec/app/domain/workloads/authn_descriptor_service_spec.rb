# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::AuthnDescriptorService do
  let(:annotation_service) { instance_double(Annotations::AnnotationService) }
  let(:res_service) { instance_double(Resources::ResourceService) }
  let(:membership_service) { instance_double(Memberships::MembershipService) }
  let(:auth_service) { instance_double(Authorisation::AuthorisationService) }
  let(:logger) { instance_double('Logger', debug?: false, debug: nil, error: nil) }

  let(:service) do
    described_class.send(:new,
                         annotation_service: annotation_service,
                         res_service: res_service,
                         membership_service: membership_service,
                         auth_service: auth_service,
                         logger: logger)
  end

  let(:role) { instance_double('Role', id: 'role-id') }
  let(:account) { 'test-account' }
  let(:member_res) { instance_double('Resource', id: 'member-id') }

  let(:api_key_descriptor) do
    instance_double('AuthnDescriptor',
                    api_key?: true,
                    type: 'api_key',
                    service_id: nil,
                    data: {},
                    branch_path: nil)
  end

  let(:cert_descriptor) do
    instance_double('AuthnDescriptor',
                    api_key?: false,
                    type: 'cert',
                    service_id: 'svc',
                    branch_path: 'conjur/authn-cert/svc',
                    data: { san_ip: ['1.2.3.4'], cn: 'example' })
  end

  before do
    allow(Authenticators::TypeConverter).to receive(:get_branch_from_type) do |type|
      case type
      when 'cert' then 'authn-cert'
      when 'jwt' then 'authn-jwt'
      when 'aws' then 'authn-iam'
      else "authn-#{type}"
      end
    end

    allow(Authenticators::TypeConverter).to receive(:get_type_from_branch) do |branch|
      case branch
      when 'authn-cert' then 'cert'
      when 'authn-jwt' then 'jwt'
      when 'authn-iam' then 'aws'
      else branch.sub('authn-', '')
      end
    end
  end

  describe '#add_descriptor_to_authenticators_group' do
    it 'returns nil for api_key descriptor' do
      expect(service.add_descriptor_to_authenticators_group(role, account, member_res, api_key_descriptor)).to be_nil
    end

    it 'adds membership for non-api-key descriptor' do
      group_res = instance_double('Resource')

      expect(auth_service).to receive(:auth_create_or_up_in_branch)
                                .with(role, account, 'conjur/authn-cert/svc')
      expect(res_service).to receive(:get_res)
                               .with(account, 'group', 'conjur/authn-cert/svc/apps')
                               .and_return(group_res)
      expect(membership_service).to receive(:check_membership_not_exist).with(group_res, member_res)
      expect(membership_service).to receive(:create_membership_db).with(group_res, member_res)

      service.add_descriptor_to_authenticators_group(role, account, member_res, cert_descriptor)
    end

    it 'raises missing authenticators permissions when forbidden' do
      allow(auth_service).to receive(:auth_create_or_up_in_branch)
                               .and_raise(ApplicationController::Forbidden)

      expect do
        service.add_descriptor_to_authenticators_group(role, account, member_res, cert_descriptor)
      end.to raise_error(Errors::Authentication::Security::MissingAuthenticatorsPermissions)
    end
  end

  describe '#collect_authn_descriptors_annotations' do
    it 'adds api-key annotation for api_key descriptor' do
      result = service.collect_authn_descriptors_annotations([api_key_descriptor])
      expect(result).to eq('authn/api-key' => 'true')
    end

    it 'builds cert annotations and normalizes key names' do
      allow(cert_descriptor).to receive(:type?).with('cert').and_return(true)
      allow(cert_descriptor).to receive(:type?).with('jwt').and_return(false)
      allow(cert_descriptor).to receive(:type?).with('aws').and_return(false)

      result = service.collect_authn_descriptors_annotations([cert_descriptor])

      expect(result).to include(
                          'authn-cert/san-ip' => '["1.2.3.4"]',
                          'authn-cert/cn' => 'example'
                        )
    end

    it 'keeps key naming for jwt data' do
      jwt_descriptor = instance_double('AuthnDescriptor',
                                       api_key?: false,
                                       type: 'jwt',
                                       service_id: 'jwt-svc',
                                       data: { claim_path: 'sub' })
      allow(jwt_descriptor).to receive(:type?).with('cert').and_return(false)
      allow(jwt_descriptor).to receive(:type?).with('jwt').and_return(true)
      allow(jwt_descriptor).to receive(:type?).with('aws').and_return(false)

      result = service.collect_authn_descriptors_annotations([jwt_descriptor])

      expect(result).to include('authn-jwt/jwt-svc/claim_path' => 'sub')
    end
  end

  describe '#regain_authn_desc_views' do
    let(:membership_1) { instance_double('RoleMembership', values: { role_id: 'test-account:group:conjur/authn-cert/svc/apps' }) }
    let(:membership_2) { instance_double('RoleMembership', values: { role_id: 'test-account:group:conjur/authn-jwt/jwt-svc/apps' }) }
    let(:dataset_1) { instance_double('Dataset') }
    let(:dataset_2) { instance_double('Dataset') }
    let(:dataset_3) { instance_double('Dataset') }
    let(:dataset_4) { instance_double('Dataset') }

    before do
      allow(::RoleMembership).to receive(:select).with(:role_id, :member_id).and_return(dataset_1)
      allow(dataset_1).to receive(:where).with(member_id: 'host-res-id', ownership: false).and_return(dataset_2)
      allow(dataset_2).to receive(:where).with(Sequel.like(:role_id, "#{account}:group:conjur/authn%")).and_return(dataset_3)
      allow(dataset_3).to receive(:where).with(Sequel.like(:role_id, '%apps%')).and_return(dataset_4)
      allow(dataset_4).to receive(:all).and_return([membership_1, membership_2])
    end

    it 'adds api_key without data when show_api_key is false' do
      authn_desc_anns = { 'authn/api-key' => 'true' }

      result = service.regain_authn_desc_views(account, 'host-res-id', authn_desc_anns, 'secret-key', false)

      expect(result).to include({ type: 'api_key' })
      expect(result).not_to include({ type: 'api_key', data: { value: 'secret-key' } })
    end
  end

  describe '#regain_service_id' do
    it 'returns default for gcp type' do
      expect(service.regain_service_id('gcp', 'acc:group:conjur/authn-gcp/apps')).to eq('default')
    end

    it 'returns service id from role id for non-gcp type' do
      expect(service.regain_service_id('cert', 'acc:group:conjur/authn-cert/my-svc/apps')).to eq('my-svc')
    end
  end
end
