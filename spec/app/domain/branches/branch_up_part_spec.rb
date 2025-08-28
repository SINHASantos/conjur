# spec/domain/branch/branch_up_part_spec.rb
require 'spec_helper'

RSpec.describe(Branches::BranchUpPart) do
  let(:owner) { {kind: 'user', id: 'alice'} }
  let(:annotations) { { 'key1' => 'value1' } }
  let(:input) { {owner:, annotations:}}

  describe '#initialize' do
    it 'sets owner and annotations' do
      part = described_class.new(**input)
      expect(part.owner.as_json.symbolize_keys).to eq(owner)
      expect(part.annotations).to eq(annotations)
    end

    it 'with empty owner when nil given' do
      part = described_class.new(**input.merge(owner: nil))
      expect(part.owner.as_json.symbolize_keys).to eq({:kind=>"", :id=>""})
      expect(part.annotations).to eq(annotations)
    end

    it 'with empty annotations when nil given' do
      part = described_class.new(**input.merge(annotations: nil))
      expect(part.owner.as_json.symbolize_keys).to eq(owner)
      expect(part.annotations).to eq({})
    end
  end
end
