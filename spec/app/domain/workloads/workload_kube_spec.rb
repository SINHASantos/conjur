# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::Workload, type: :model do
  let(:valid_name) { 'test-workload' }
  let(:valid_branch) { 'data/branch' }
  let(:valid_type) { Workloads::Workload::KUBE_TYPE }
  let(:valid_subtype) { Workloads::Workload::KUBE_SUBTYPE_DEFAULT }
  let(:valid_owner_id) { 'rspec:user:owner-id' }
  let(:valid_owner) { { kind: 'user', id: 'alice' } }
  let(:valid_authn_descriptors) { [{ "type": "api_key" }] }
  let(:valid_annotations) { Annotations::Annotations.new({ 'key1' => 'value1' }) }
  let(:valid_restricted_to) { ['192.168.1.1'] }
  let(:valid_restricted_to_cidr) { ['192.168.1.1/32'] }

  let(:input) { { name: valid_name, branch: valid_branch, type: valid_type,
                  subtype: valid_subtype, owner: valid_owner, annotations: valid_annotations,
                  restricted_to: valid_restricted_to, authn_descriptors: valid_authn_descriptors } }

  def check_workload(workload, subtype = valid_subtype)
    expect(workload.name).to eq(valid_name)
    expect(workload.branch).to eq(valid_branch)
    expect(workload.type).to eq(valid_type)
    expect(workload.subtype).to eq(subtype)
    expect(workload.owner.as_json.symbolize_keys).to eq(valid_owner)
    expect(workload.authn_descriptors.to_json).to eq(valid_authn_descriptors.to_json)
    expect(workload.annotations).to eq(valid_annotations)
    expect(workload.restricted_to).to eq(valid_restricted_to_cidr)
  end

  describe "initialization a workload with 'kubernetes' type" do
    subtypes = Workloads::Workload::KUBE_SUBTYPES
    subtypes += [nil, '', ' ']
    subtypes.each do |kube_subtype|
      it "creates a valid workload with subtype '#{kube_subtype}'" do
        workload = described_class.new(**input.merge(subtype: kube_subtype))
        ks = if kube_subtype.to_s.strip.empty?
               Workloads::Workload::KUBE_SUBTYPE_DEFAULT
             else
               kube_subtype
             end
        check_workload(workload, ks)
      end
    end

    (Workloads::Workload::TYPES - [Workloads::Workload::KUBE_TYPE])
      .each do |invalid_type|
      it "raises DomainValidationError when type has invalid value = '#{invalid_type}'" do
        expect {
          described_class.new(**input.merge(type: invalid_type))
        }.to raise_error(Validation::DomainValidationError,
                         "Subtype is only allowed for type 'kubernetes'")
      end
    end

    [nil, '', ' ']
      .each do |invalid_type|
      it "raises DomainValidationError when type has invalid value = '#{invalid_type}'" do
        expect {
          described_class.new(**input.merge(type: invalid_type))
        }.to raise_error(Validation::DomainValidationError,
                         "Subtype is only allowed for type 'kubernetes'")
      end
    end

    ['some_string', 'some-string', 'some string']
      .each do |invalid_type|
      it "raises DomainValidationError when type has invalid value = '#{invalid_type}'" do
        expect {
          described_class.new(**input.merge(type: invalid_type))
        }.to raise_error(Validation::DomainValidationError,
                         "Type contains unsupported value: #{invalid_type}")
      end
    end

    [:symbol, 34, true, [], {}, //]
      .each do |invalid_type|
      it "raises DomainValidationError when type has invalid value = '#{invalid_type}'" do
        expect {
          described_class.new(**input.merge(type: invalid_type))
        }.to raise_error(Validation::DomainValidationError,
                         /Type must be a string/)
      end
    end

    ['some_string', 'some-string', 'some string']
      .each do |invalid_subtype|
      it "raises DomainValidationError when subtype has invalid value = '#{invalid_subtype}'" do
        expect {
          described_class.new(**input.merge(subtype: invalid_subtype))
        }.to raise_error(Validation::DomainValidationError,
                         "Subtype must be one of: gke, openshift, eks, aks")
      end
    end

    [:symbol, 34, true, [], {}, //]
      .each do |invalid_subtype|
      it "raises DomainValidationError when subtype has invalid value = '#{invalid_subtype}'" do
        expect {
          described_class.new(**input.merge(subtype: invalid_subtype))
        }.to raise_error(Validation::DomainValidationError,
                         "Subtype must be a string")
      end
    end
  end
end
