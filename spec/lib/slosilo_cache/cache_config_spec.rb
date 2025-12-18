# frozen_string_literal: true

require 'spec_helper'
require Rails.root.join('lib/slosilo_cache/cache_config')
require Rails.root.join('lib/slosilo_cache/cache_adapter')

describe(SlosiloCache::CacheConfig) do
  let(:logger) { instance_double(Logger) }
  let(:feature_flags) { instance_double('FeatureFlags') }
  let(:base_adapter) { instance_double('BaseAdapter') }
  let(:cache) { instance_double('Cache') }

  before do
    allow(logger).to receive(:info)

    # Ensure Slosilo.adapter has a known initial value
    @original_adapter = Slosilo.adapter
    Slosilo.adapter = base_adapter
  end

  after do
    # Reset any adapter changes to avoid leakage between examples
    Slosilo.adapter = @original_adapter
  end

  describe '.configure' do
    context 'when slosilo_key_cache feature flag is enabled' do
      before do
        allow(feature_flags).to receive(:enabled?).with(:slosilo_key_cache).and_return(true)
      end

      it 'wraps Slosilo.adapter with CacheAdapter' do
        result = described_class.configure(
          feature_flags: feature_flags,
          logger: logger,
          adapter: base_adapter,
          cache: cache
        )

        expect(result).to be(true)
        expect(Slosilo.adapter).to be_a(SlosiloCache::CacheAdapter)
      end

      it 'logs that the key will be cached' do
        described_class.configure(
          feature_flags: feature_flags,
          logger: logger,
          adapter: base_adapter,
          cache: cache
        )

        expect(logger).to have_received(:info).with('Slosilo encryption key will be cached')
      end
    end

    context 'when slosilo_key_cache feature flag is disabled' do
      before do
        allow(feature_flags).to receive(:enabled?).with(:slosilo_key_cache).and_return(false)
      end

      it 'does not change the Slosilo.adapter' do
        result = described_class.configure(
          feature_flags: feature_flags,
          logger: logger,
          adapter: base_adapter,
          cache: cache
        )

        expect(result).to be(false)
        expect(Slosilo.adapter).to be(base_adapter)
      end

      it 'logs that the cache is disabled' do
        described_class.configure(
          feature_flags: feature_flags,
          logger: logger,
          adapter: base_adapter,
          cache: cache
        )

        expect(logger).to have_received(:info).with('Slosilo encryption key cache is disabled')
      end
    end
  end
end
