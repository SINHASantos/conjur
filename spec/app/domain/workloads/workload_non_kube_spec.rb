# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::Workload, type: :model do
  let(:valid_name) { 'test-workload' }
  let(:valid_branch) { 'data/branch' }
  let(:non_kube_types) { (Workloads::Workload::TYPES - [Workloads::Workload::KUBE_TYPE]) }
  let(:valid_type) { non_kube_types.sample }
  let(:valid_subtype) { '' }
  let(:valid_owner_id) { 'rspec:user:owner-id' }
  let(:valid_owner) { { kind: 'user', id: 'alice' } }
  let(:valid_authn_descriptors) { [{ "type": "api_key" }] }
  let(:valid_annotations) { Annotations::Annotations.new({ 'key1' => 'value1' }) }
  let(:valid_restricted_to) { ['192.168.1.1'] }
  let(:valid_restricted_to_cidr) { ["192.168.1.1/32"] }

  let(:input) { { name: valid_name, branch: valid_branch, type: valid_type,
                  subtype: valid_subtype, owner: valid_owner, annotations: valid_annotations,
                  restricted_to: valid_restricted_to, authn_descriptors: valid_authn_descriptors } }

  def check_workload(workload, type)
    expect(workload.name).to eq(valid_name)
    expect(workload.branch).to eq(valid_branch)
    expect(workload.type).to eq(type)
    expect(workload.subtype).to eq(valid_subtype)
    expect(workload.owner.as_json.symbolize_keys).to eq(valid_owner)
    expect(workload.authn_descriptors.to_json).to eq(valid_authn_descriptors.to_json)
    expect(workload.annotations).to eq(valid_annotations)
    expect(workload.restricted_to).to eq(valid_restricted_to_cidr)
  end

  describe "initialization a workload with not 'kubernetes' type" do
    types = (Workloads::Workload::TYPES - [Workloads::Workload::KUBE_TYPE])
    types += [nil, '', ' ']
    types.each do |type|
      [nil, ''].each do |subtype|
        it "creates a valid workload with type '#{type}'" do
          workload = described_class.new(**input.merge(type: type, subtype: subtype))
          check_workload(workload, type.to_s.strip.empty? ? 'other' : type)
        end
      end
    end

    invalid_types = [Workloads::Workload::KUBE_TYPE]
    invalid_types += ['some_string', :symbol, 34, true, [], {}, //]
    invalid_types.each do |invalid_type|
      it "raises DomainValidationError when type has invalid value = '#{invalid_type}'" do
        expect {
          described_class.new(**input.merge(type: invalid_type, subtype: 'non_kube_subtype'))
        }.to raise_error(Validation::DomainValidationError)
      end
    end

    (Workloads::Workload::TYPES - [Workloads::Workload::KUBE_TYPE]).each do |type|
      [:symbol, 34, true, [], {}, //]
        .each do |invalid_subtype|
        it "raises DomainValidationError when type is '#{type}' and subtype has invalid value = '#{invalid_subtype}'" do
          expect {
            described_class.new(**input.merge(type: type, subtype: invalid_subtype))
          }.to raise_error(Validation::DomainValidationError,
                           "Subtype must be a string")
        end
      end
    end

    (Workloads::Workload::TYPES - [Workloads::Workload::KUBE_TYPE]).each do |type|
      invalid_subtypes = [Workloads::Workload::KUBE_SUBTYPE_DEFAULT]
      invalid_subtypes += [' ', 'some_string', 'some-string', 'some string']
      invalid_subtypes
        .each do |invalid_subtype|
        it "raises DomainValidationError when type is '#{type}' and subtype has invalid value = '#{invalid_subtype}'" do
          expect {
            described_class.new(**input.merge(type: type, subtype: invalid_subtype))
          }.to raise_error(Validation::DomainValidationError,
                           "Subtype is only allowed for type 'kubernetes'")
        end
      end
    end
  end
end
