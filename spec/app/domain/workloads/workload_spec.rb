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
                         "Authn descriptors must be an array with exactly one descriptor")
      end
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
  end
end
