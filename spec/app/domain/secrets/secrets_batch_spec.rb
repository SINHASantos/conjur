# frozen_string_literal: true

require 'spec_helper'

describe Secrets::SecretsBatch do
  let(:max_size) { described_class::IDS_MAX_SIZE }
  let(:base64) { described_class::BASE_64 }

  describe '#initialize' do
    context 'with valid parameters' do
      it 'creates instance with required ids parameter' do
        batch = described_class.new(ids: ['data/var1'])
        expect(batch.ids).to eq(['data/var1'])
        expect(batch.encode_values).to eq('')
      end

      it 'creates instance with ids and encode_values' do
        batch = described_class.new(ids: ['data/var1'], encode_values: base64)
        expect(batch.ids).to eq(['data/var1'])
        expect(batch.encode_values).to eq(base64)
      end

      it 'accepts empty encode_values string' do
        expect { described_class.new(ids: ['data/var1'], encode_values: '') }.not_to raise_error
      end

      it 'accepts multiple ids' do
        batch = described_class.new(ids: %w[data/var1 data/var2 data/var3])
        expect(batch.ids.length).to eq(3)
      end
    end

    context 'with missing or invalid required parameters' do
      it 'raises error when ids parameter is missing' do
        expect { described_class.new(encode_values: '') }
          .to raise_error(Validation::DomainValidationError, "Ids can't be blank and Ids must be an array")
      end

      it 'raises error when ids is nil' do
        expect { described_class.new(ids: nil) }
          .to raise_error(Validation::DomainValidationError, /Ids can't be blank/)
      end

      it 'raises error when ids is not an array' do
        expect { described_class.new(ids: 'not_an_array') }
          .to raise_error(Validation::DomainValidationError, /Ids must be an array/)
      end

      it 'raises error when ids array contains non-string elements' do
        expect { described_class.new(ids: ['valid', 123, 'another']) }
          .to raise_error(Validation::DomainValidationError, /can only contain strings/)
      end

      it 'raises error when ids array contains nil' do
        expect { described_class.new(ids: ['valid', nil]) }
          .to raise_error(Validation::DomainValidationError, /can only contain strings/)
      end
    end

    context 'with encode_values validation' do
      it 'raises error when encode_values is not a string' do
        expect { described_class.new(ids: ['data/var1'], encode_values: 123) }
          .to raise_error(Validation::DomainValidationError, "Encode values must be a string and Encode values The encode_values query parameter must be base64: encode_values=base64")
      end

      it 'raises error when encode_values is invalid value' do
        expect { described_class.new(ids: ['data/var1'], encode_values: 'invalid') }
          .to raise_error(Validation::DomainValidationError, /must be #{base64}/)
      end

      it 'accepts base64 encode_values' do
        expect { described_class.new(ids: ['data/var1'], encode_values: base64) }
          .not_to raise_error
      end
    end

    context 'with batch size limits' do
      it 'accepts ids up to maximum size' do
        ids = Array.new(max_size, 'data/var')
        expect { described_class.new(ids: ids) }.not_to raise_error
      end

      it 'raises error when ids exceed maximum size' do
        ids = Array.new(max_size + 1, 'data/var')
        expect { described_class.new(ids: ids) }
          .to raise_error(Errors::Conjur::BatchRequestExceededMaxSize, /#{max_size}/)
      end
    end

    context 'with id normalization' do
      it 'strips single leading slash from id' do
        batch = described_class.new(ids: ['/data/var1'])
        expect(batch.ids).to eq(['data/var1'])
      end

      it 'strips leading slash from multiple ids' do
        batch = described_class.new(ids: ['/data/var1', '/data/var2'])
        expect(batch.ids).to eq(%w[data/var1 data/var2])
      end

      it 'preserves ids without leading slash' do
        batch = described_class.new(ids: ['data/var1', 'data/var2'])
        expect(batch.ids).to eq(%w[data/var1 data/var2])
      end

      it 'handles mixed ids with and without leading slash' do
        batch = described_class.new(ids: ['data/var1', '/data/var2', 'data/var3'])
        expect(batch.ids).to eq(%w[data/var1 data/var2 data/var3])
      end

      it 'preserves order after normalization' do
        batch = described_class.new(ids: ['/data/var2', 'data/var1', '/data/var3'])
        expect(batch.ids).to eq(%w[data/var2 data/var1 data/var3])
      end
    end

    context 'with invalid id formats' do
      it 'raises error when id starts with double slash' do
        expect { described_class.new(ids: ['//data/var1']) }
          .to raise_error(Validation::DomainValidationError, /invalid/)
      end

      it 'raises error when multiple ids have double slashes' do
        expect { described_class.new(ids: ['data/var1', '//data/var2']) }
          .to raise_error(Validation::DomainValidationError, /invalid/)
      end

      it 'includes invalid id in error message' do
        expect { described_class.new(ids: ['//invalid/id']) }
          .to raise_error(Validation::DomainValidationError, /\/\/invalid\/id/)
      end
    end

    context 'with dynamic secret validation' do
      it 'raises error for dynamic secret ids' do
        dynamic_id = "#{Issuer::DYNAMIC_VARIABLE_PREFIX}var1"
        expect { described_class.new(ids: [dynamic_id]) }
          .to raise_error(ApplicationController::UnprocessableEntity, /dynamic secrets/)
      end

      it 'raises error when dynamic secret is among valid ids' do
        dynamic_id = "#{Issuer::DYNAMIC_VARIABLE_PREFIX}var1"
        expect { described_class.new(ids: ['data/var1', dynamic_id]) }
          .to raise_error(ApplicationController::UnprocessableEntity, /dynamic secrets/)
      end

      it 'accepts non-dynamic ids that start with similar prefix' do
        expect { described_class.new(ids: ['data/dynamic_var']) }.not_to raise_error
      end
    end
  end

  describe '#use_base64?' do
    it 'returns true when encode_values is base64' do
      batch = described_class.new(ids: ['data/var1'], encode_values: base64)
      expect(batch.use_base64?).to be true
    end

    it 'returns false when encode_values is empty string' do
      batch = described_class.new(ids: ['data/var1'], encode_values: '')
      expect(batch.use_base64?).to be false
    end

    it 'returns false when encode_values is not provided' do
      batch = described_class.new(ids: ['data/var1'])
      expect(batch.use_base64?).to be false
    end
  end

  describe '#to_s' do
    it 'includes ids in string representation' do
      batch = described_class.new(ids: ['data/var1'])
      expect(batch.to_s).to include('ids=')
      expect(batch.to_s).to include('data/var1')
    end

    it 'includes encode_values in string representation' do
      batch = described_class.new(ids: ['data/var1'], encode_values: base64)
      expect(batch.to_s).to include("encode_values=#{base64}")
    end

    it 'shows class name in string representation' do
      batch = described_class.new(ids: ['data/var1'])
      expect(batch.to_s).to include('SecretsBatch')
    end
  end

  describe 'edge cases' do
    it 'handles empty ids array after validation passes' do
      expect { described_class.new(ids: []) }
        .to raise_error(Validation::DomainValidationError)
    end

    it 'handles ids with special characters' do
      batch = described_class.new(ids: ['data/var-1', 'data/var_2', 'data/var.3'])
      expect(batch.ids).to eq(['data/var-1', 'data/var_2', 'data/var.3'])
    end

    it 'handles deeply nested paths' do
      batch = described_class.new(ids: ['data/path/to/deep/nested/var'])
      expect(batch.ids).to eq(['data/path/to/deep/nested/var'])
    end
  end
end
