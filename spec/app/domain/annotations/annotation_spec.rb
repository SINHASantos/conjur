# spec/domain/annotation/annotation_spec.rb
require 'spec_helper'

RSpec.describe(Annotations::Annotations) do

  describe 'initialization' do
    let(:input) { { 'valid-key' => 'valid value',
                    'another_key' => 'another value' }.symbolize_keys }

    def check_annotations(annotations)
      expect(annotations).to eq(input)
    end

    it "creates a valid Annotations object with valid input" do
      annotations = described_class.new(input)
      check_annotations(annotations)
    end

    it 'is invalid if annotation key is reserved' do
      expect {
        described_class.new(**input.merge({ Annotations::Annotations::FORBIDDEN_KEY => 'some value' }))
      }.to raise_error(Validation::DomainValidationError,
                       /The annotation key 'type' is reserved and cannot be used/)
    end

    ['va<lue', 'va>lue', "va'lue", 'a' * (Validation::PATH_LENGTH_MAX + 1)]
      .each do |invalid_key|
      it 'raises error for invalid key format' do
        expect {
          described_class.new({ invalid_key => 'some_value' })
        }.to raise_error(Validation::DomainValidationError,
                         /Invalid 'annotation name' parameter./)
      end
    end

    ['va<lue', 'va>lue', "va'lue", 'a' * (Annotations::Annotations::VALUE_LENGTH_MAX + 1)]
      .each do |invalid_value|
      it "raises error for invalid value #{invalid_value}" do
        expect {
          described_class.new({ "foo": invalid_value })
        }.to raise_error(Validation::DomainValidationError,
                         /Invalid 'annotation value'./)
      end
    end

    [nil, '']
      .each do |missing_value|
      it 'with missing value' do
        expect {
          described_class.new(**input.merge({ foo: missing_value }))
        }.to raise_error(Errors::Conjur::ParameterMissing,
                         /CONJ00190W Missing required parameter:/)
      end
    end

    describe '.from_model' do
      let(:model) do
        [
          double('Annotation', name: 'a', value: '1'),
          double('Annotation', name: 'b', value: '2')
        ]
      end

      it 'returns a hash of name => value' do
        result = described_class.from_model(model)
        expect(result).to eq({ 'a' => '1', 'b' => '2' })
      end

      it 'returns empty hash for empty model' do
        expect(described_class.from_model([])).to eq({})
      end
    end
  end
end
