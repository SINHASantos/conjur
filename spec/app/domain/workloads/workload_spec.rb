# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::Workload, type: :model do
  let(:valid_name) { 'test-workload' }
  let(:valid_branch) { 'data/branch' }
  let(:valid_type) { 'jenkins' }
  let(:valid_type_kube) { 'kubernetes' }
  let(:valid_subtype) { '' }
  let(:valid_subtype_kube) { 'openshift' }
  let(:valid_owner_id) { 'rspec:user:owner-id' }
  let(:valid_owner) { { kind: 'user', id: 'alice' } }
  let(:valid_authn_descriptors) { [{ "type": "api_key" }.symbolize_keys] }
  let(:valid_annotations) { { 'key1' => 'value1' }.symbolize_keys }
  let(:valid_restricted_to) { ['192.168.1.1', '10.0.0.0/8'] }
  let(:valid_restricted_to_saved) { ["192.168.1.1/32", '10.0.0.0/8'] }

  let(:input) { { name: valid_name, branch: valid_branch, type: valid_type,
                  subtype: valid_subtype, owner: valid_owner, annotations: valid_annotations,
                  restricted_to: valid_restricted_to,
                  authn_descriptors: valid_authn_descriptors }.deep_symbolize_keys }

  def check_workload(workload,
                     type: valid_type, subtype: valid_subtype,
                     owner: valid_owner)
    expect(workload.name).to eq(valid_name)
    expect(workload.branch).to eq(valid_branch)
    expect(workload.type).to eq(type)
    expect(workload.subtype).to eq(subtype)
    expect(workload.owner.as_json.symbolize_keys).to eq(owner.symbolize_keys)
    expect(workload.authn_descriptors.map(&:as_json).map(&:symbolize_keys)).to eq(valid_authn_descriptors.map(&:symbolize_keys))
    expect(workload.annotations).to eq(valid_annotations)
    expect(workload.restricted_to).to eq(valid_restricted_to_saved)
  end

  describe 'initialization' do

    it 'creates a valid workload with valid inputs' do
      workload = described_class.new(**input)
      check_workload(workload)
    end

    # name
    [nil, '', ' ', 'ab', 'some string', 'some=string',
     "a" * (Workloads::Workload::NAME_LENGTH_MIN - 1),
     "a" * (Workloads::Workload::NAME_LENGTH_MAX + 1),
     :symbol, 34, true, [], {}, //]
      .each do |invalid_name|
      it "raises DomainValidationError when name has invalid value = '#{invalid_name}'" do
        expect {
          described_class.new(**input.merge(name: invalid_name))
        }.to raise_error(Validation::DomainValidationError)
      end
    end

    # branch
    [nil, '', ' ', 'some string', 'some=string',
     "a" * (Validation::PATH_LENGTH_MIN - 1),
     "a" * (Validation::PATH_LENGTH_MAX + 1),
     :symbol, 34, true, [], {}, //]
      .each do |invalid_branch|
      it "raises DomainValidationError when branch has invalid value = '#{invalid_branch}'" do
        expect {
          described_class.new(**input.merge(branch: invalid_branch))
        }.to raise_error(Validation::DomainValidationError)
      end
    end

    # owner
    it 'creates a valid workload with valid owner' do
      workload = described_class.new(**input)
      check_workload(workload)
    end

    [{ kind: 'user' }, { id: 'alice' }, {}, { a: 'x', b: 'y' }]
      .each do |invalid_owner|
      it "raises DomainValidationError when owner has invalid hash = '#{invalid_owner}'" do
        expect {
          described_class.new(**input.merge(owner: invalid_owner))
        }.to raise_error(Validation::DomainValidationError,
                         /Owner must contain both 'kind' and 'id' field/) # TODO other ma=essages
      end
    end

    # authn_descriptors
    [nil, '', ' ', 'some string', 'some=string', :symbol, 34, true, [], {}, //]
      .each do |invalid_authn_desc|
      it "raises DomainValidationError when authn descriptor has invalid value = '#{invalid_authn_desc}'" do
        expect {
          described_class.new(**input.merge(authn_descriptors: invalid_authn_desc))
        }.to raise_error(Validation::DomainValidationError,
                         /authn_descriptors.*must be an array with one or two descriptors/i)
      end
    end

    it 'raises when authn_descriptors array is empty' do
      expect {
        described_class.new(**input.merge(authn_descriptors: []))
      }.to raise_error(Validation::DomainValidationError,
                       /authn_descriptors.*must be an array with one or two descriptors/i)
    end

    it 'raises when authn_descriptors has more than two elements' do
      descriptors = [
        { type: 'api_key' },
        { type: 'jwt', service_id: 'jwtsvc', data: {} },
        { type: 'aws', service_id: 'awssvc', data: {} }
      ]

      expect {
        described_class.new(**input.merge(authn_descriptors: descriptors))
      }.to raise_error(Validation::DomainValidationError,
                       /authn_descriptors.*must be an array with one or two descriptors/i)
    end

    it 'raises when a non-repeatable authn type appears more than once' do
      descriptors = [
        { type: 'api_key' },
        { type: 'api_key' }
      ]

      expect {
        described_class.new(**input.merge(authn_descriptors: descriptors))
      }.to raise_error(Validation::DomainValidationError,
                       /Each authn type .* can appear at most once/i)
    end

    it 'allows duplicate repeatable authn type jwt' do
      descriptors = [
        { type: 'jwt', service_id: 'jwtsvc1', data: {} },
        { type: 'jwt', service_id: 'jwtsvc2', data: {} }
      ]

      expect {
        described_class.new(**input.merge(authn_descriptors: descriptors))
      }.not_to raise_error
    end

    it 'allows duplicate repeatable authn type azure' do
      descriptors = [
        { type: 'azure', service_id: 'azuresvc1', data: {} },
        { type: 'azure', service_id: 'azuresvc2', data: {} }
      ]

      expect {
        described_class.new(**input.merge(authn_descriptors: descriptors))
      }.not_to raise_error
    end

    it 'raises for duplicate cert authn type with current validation list' do
      descriptors = [
        { type: 'cert', service_id: 'certsvc1', data: {} },
        { type: 'cert', service_id: 'certsvc2', data: {} }
      ]

      expect {
        described_class.new(**input.merge(authn_descriptors: descriptors))
      }.to raise_error(Validation::DomainValidationError,
                       /Each authn type .* can appear at most once/i)
    end

    it 'propagates descriptor validation errors with descriptor index' do
      descriptors = [
        { type: 'jwt', service_id: '', data: {} }
      ]

      expect {
        described_class.new(**input.merge(authn_descriptors: descriptors))
      }.to raise_error(Validation::DomainValidationError,
                       /in authn_descriptors\[0\]/)
    end

    # annotations
    it 'raises DomainValidationError if annotation key is reserved' do
      expect {
        described_class.new(**input.merge(annotations: { 'type' => 'foo' }))
      }.to raise_error(Validation::DomainValidationError,
                       /reserved/)
    end

    [:symbol, 34, true, [], {}, //]
      .each do |invalid_ann_value|
      it "raises DomainValidationError when annotation value has invalid value = '#{invalid_ann_value}'" do
        expect {
          described_class.new(**input.merge(annotations: { foo: invalid_ann_value }))
        }.to raise_error(Validation::DomainValidationError,
                         /must be of 'type=string'/)
      end
    end

    [nil, '']
      .each do |missing_ann_value|
      it "raises DomainValidationError wif annotation value is nil" do
        expect {
          described_class.new(**input.merge(annotations: { foo: missing_ann_value }))
        }.to raise_error(Errors::Conjur::ParameterMissing,
                         /CONJ00190W Missing required parameter: foo/)
      end
    end

    it 'is invalid if annotation value has invalid format' do
      expect {
        described_class.new(**input.merge(annotations: { 'foo' => "bad<lue" })).valid?
      }.to raise_error(Validation::DomainValidationError,
                       /Invalid 'annotation value'/)
    end

    it 'raises if annotations is not a hash' do
      expect {
        described_class.new(**input.merge(annotations: 'not a hash')).valid?
      }.to raise_error(Validation::DomainValidationError,
                       /Must be a dictionary/)
    end

    it 'raises if more than 20 annotations' do
      too_many = (1..Workloads::Workload::MAX_ANNOTATIONS_SIZE + 1).map { |i| ["k#{i}", "v#{i}"] }.to_h
      expect {
        described_class.new(**input.merge(annotations: too_many))
      }.to raise_error(Validation::DomainValidationError,
                       /more than 20/)
    end

    # restricted_to

    it 'raises DomainValidationError when restricted_to has too many entries' do
      allow(Rails.application.config).to receive_message_chain(:conjur_config, :max_restricted_to).and_return(2)
      expect {
        described_class.new(**input.merge(restricted_to: ['1.1.1.1', '2.2.2.2', '3.3.3.3']))
      }.to raise_error(Validation::DomainValidationError,
                       /Too many CIDR entries/)
    end

    it 'raises DomainValidationError when restricted_to has invalid IP' do
      expect {
        described_class.new(**input.merge(restricted_to: ['invalid_ip']))
      }.to raise_error(Validation::DomainValidationError,
                       /Invalid IP address or CIDR range/)
    end

    ['', ' ', 'some string', 'some=string', :symbol, 34, true, {}, //]
      .each do |invalid_restricted_to|
      it "raises DomainValidationError when restricted_to has invalid value = '#{invalid_restricted_to}'" do
        expect {
          described_class.new(**input.merge(restricted_to: invalid_restricted_to))
        }.to raise_error(Validation::DomainValidationError,
                         /restricted_to must be an array/)
      end
    end

    # type
    it 'defaults type to other when type is nil' do
      workload = described_class.new(**input.merge(type: nil))
      expect(workload.type).to eq('other')
    end

    it 'defaults type to other when type is blank string' do
      workload = described_class.new(**input.merge(type: ''))
      expect(workload.type).to eq('other')
    end

    it 'defaults type to other when type is whitespace' do
      workload = described_class.new(**input.merge(type: '   '))
      expect(workload.type).to eq('other')
    end

    it 'normalizes type to lowercase' do
      workload = described_class.new(**input.merge(type: 'JENKINS'))
      expect(workload.type).to eq('jenkins')
    end

    ['invalid_type']
      .each do |invalid_type|
      it "raises DomainValidationError when type has unsupported value = '#{invalid_type}'" do
        expect {
          described_class.new(**input.merge(type: invalid_type))
        }.to raise_error(Validation::DomainValidationError,
                         /contains unsupported value/i)
      end
    end

    [:symbol, 34, true, [], {}, //]
      .each do |invalid_type|
      it "raises DomainValidationError when type has non-string value = '#{invalid_type}'" do
        expect {
          described_class.new(**input.merge(type: invalid_type))
        }.to raise_error(Validation::DomainValidationError,
                         /Type must be a String/i)
      end
    end

    # subtype
    it 'raises DomainValidationError when subtype is invalid for kubernetes type' do
      expect {
        described_class.new(**input.merge(type: 'kubernetes', subtype: 'invalid_subtype'))
      }.to raise_error(Validation::DomainValidationError,
                       /must be one of: gke, openshift, eks, aks/)
    end

    it 'raises DomainValidationError when subtype is not empty for non-kubernetes type' do
      expect {
        described_class.new(**input.merge(type: 'jenkins', subtype: 'non_empty'))
      }.to raise_error(Validation::DomainValidationError,
                       /is only allowed for type 'kubernetes'/)
    end

    it 'defaults subtype to openshift for kubernetes type when subtype is blank' do
      workload = described_class.new(**input.merge(type: 'kubernetes', subtype: ''))
      expect(workload.subtype).to eq('openshift')
    end

    it 'sets subtype to empty for non-kubernetes type when subtype is nil' do
      workload = described_class.new(**input.merge(type: 'jenkins', subtype: nil))
      expect(workload.subtype).to eq('')
    end

    # owner
    it 'creates workload with default owner when owner is nil' do
      workload = described_class.new(**input.merge(owner: nil))
      expect(workload.owner).to be_a(Branches::Owner)
      expect(workload.owner.set?).to be(false)
    end

    ['invalid_kind']
      .each do |invalid_kind|
      it "raises DomainValidationError when owner kind has invalid value = '#{invalid_kind}'" do
        expect {
          described_class.new(**input.merge(owner: { kind: invalid_kind, id: 'alice' }))
        }.to raise_error(Validation::DomainValidationError,
                         /valid owner kind/i)
      end
    end

    [nil, '', ' ', 'invalid id', :symbol, 34, true, [], {}, //]
      .each do |invalid_id|
      it "raises DomainValidationError when owner id has invalid value = '#{invalid_id}'" do
        expect {
          described_class.new(**input.merge(owner: { kind: 'user', id: invalid_id }))
        }.to raise_error(Validation::DomainValidationError,
                         /string|path|blank/i)
      end
    end

    # authn_descriptors - additional valid combinations
    it 'accepts two descriptors with different non-repeatable types' do
      descriptors = [
        { type: 'api_key' },
        { type: 'aws', service_id: 'awssvc', data: {} }
      ]

      expect {
        described_class.new(**input.merge(authn_descriptors: descriptors))
      }.not_to raise_error
    end

    # annotations defaults
    it 'creates workload with empty annotations when annotations is nil' do
      workload = described_class.new(**input.merge(annotations: nil))
      expect(workload.annotations).to eq({})
    end
  end
end
