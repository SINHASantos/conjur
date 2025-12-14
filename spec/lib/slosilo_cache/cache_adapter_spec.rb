# frozen_string_literal: true

require 'spec_helper'

require 'slosilo'
require 'slosilo_cache/cache_adapter'

describe SlosiloCache::CacheAdapter do
  class DummyAdapter < Slosilo::Adapters::AbstractAdapter
    attr_reader :get_key_calls, :get_by_fingerprint_calls, :put_key_calls, :each_calls 

    def initialize
      super()
      @store = {}         # id => Slosilo::Key
      @fp_index = {}      # fingerprint => id
      @get_key_calls = 0
      @get_by_fingerprint_calls = 0
      @put_key_calls = 0
      @each_calls = 0
    end

    def existing
      :existing_called
    end

    def put_key(id, key)
      @put_key_calls += 1
      @store[id] = key
      @fp_index[key.fingerprint] = id
      true
    end

    def get_key(id)
      @get_key_calls += 1
      @store[id]
    end

    def get_by_fingerprint(fp)
      @get_by_fingerprint_calls += 1
      id = @fp_index[fp]
      return nil unless id

      [@store[id], id]
    end

    def each(&blk)
      @each_calls += 1
      @store.each_pair do |id, key|
        blk.call(id, key)
      end
    end
  end

  # Minimal cache implementation expected by adapter
  class FakeCache
    def initialize
      @h = {}
      @clear_count = 0
    end

    def get(id)
      @h[id]
    end

    def get_by_fingerprint(fingerprint)
      @h.each_pair do |id, key|
        return [key, id] if key.respond_to?(:fingerprint) && key.fingerprint == fingerprint
      end
      nil
    end

    def put(id, key)
      @h[id] = key
    end

    def clear!
      @clear_count += 1
      @h.clear
    end

    def clear_count
      @clear_count
    end
  end

  let(:wrapped) { DummyAdapter.new }
  let(:cache) { FakeCache.new }
  let(:logger) { instance_double('Logger', info: nil, debug: nil) }
  let(:adapter) { described_class.new(wrapped, cache, logger) }

  # Utility to build a Slosilo::Key and stable fingerprint
  def new_key
    Slosilo::Key.new
  end

  describe '#get_key' do
    it 'returns nil when wrapped adapter misses and caches nothing' do
      expect(adapter.get_key('missing')).to be_nil
      expect(wrapped.get_key_calls).to eq(1)
    end

    it 'caches value on hit and avoids calling wrapped adapter next time' do
      key = new_key
      wrapped.put_key('k1', key)

      # first call => hits wrapped, populates cache
      expect(adapter.get_key('k1')).to eq(key)
      expect(wrapped.get_key_calls).to eq(1)

      # second call => serves from cache
      expect(adapter.get_key('k1')).to eq(key)
      expect(wrapped.get_key_calls).to eq(1)
    end
  end

  describe '#get_by_fingerprint' do
    it 'delegates to wrapped adapter and caches by id' do
      key = new_key
      wrapped.put_key('byfp1', key)

      fp = key.fingerprint
      pair = adapter.get_by_fingerprint(fp)
      expect(pair).to eq([key, 'byfp1'])
      expect(wrapped.get_by_fingerprint_calls).to eq(1)

      # Now get_key should be served from cache
      expect(adapter.get_key('byfp1')).to eq(key)
      expect(wrapped.get_key_calls).to eq(0)
    end

    it 'returns nil when wrapped returns nil' do
      expect(adapter.get_by_fingerprint('nope')).to be_nil
      expect(wrapped.get_by_fingerprint_calls).to eq(1)
    end
  end

  describe '#get_by_fingerprint with cache' do
    it 'serves from cache when fingerprint is present in cache' do
      key = new_key
      # Populate cache via adapter (also populates wrapped)
      adapter.put_key('byfp_cache', key)

      fp = key.fingerprint

      # First call should hit cache, not wrapped
      pair = adapter.get_by_fingerprint(fp)
      expect(pair).to eq([key, 'byfp_cache'])
      expect(wrapped.get_by_fingerprint_calls).to eq(0)

      # Subsequent call also from cache
      pair2 = adapter.get_by_fingerprint(fp)
      expect(pair2).to eq([key, 'byfp_cache'])
      expect(wrapped.get_by_fingerprint_calls).to eq(0)
    end
  end

  describe '#put_key' do
    it 'stores in wrapped and cache' do
      key = new_key
      adapter.put_key('put1', key)

      # Should be in cache, no wrapped call on get_key
      expect(adapter.get_key('put1')).to eq(key)
      expect(wrapped.put_key_calls).to eq(1)
      expect(wrapped.get_key_calls).to eq(0)
    end
  end

  describe '#each' do
    it 'yields entries and fills cache' do
      k1 = new_key
      k2 = new_key
      wrapped.put_key('e1', k1)
      wrapped.put_key('e2', k2)

      yielded = {}
      adapter.each do |id, key|
        yielded[id] = key
      end

      expect(yielded).to eq('e1' => k1, 'e2' => k2)
      expect(wrapped.each_calls).to eq(1)

      # Subsequent get_key served from cache
      expect(adapter.get_key('e1')).to eq(k1)
      expect(adapter.get_key('e2')).to eq(k2)
      expect(wrapped.get_key_calls).to eq(0)
    end
  end

  describe '#clear_cache!' do
    it 'clears committed cache' do
      k = new_key
      wrapped.put_key('c1', k)
      expect(adapter.get_key('c1')).to eq(k)
      expect(wrapped.get_key_calls).to eq(1)

      adapter.clear_cache!
      # After clear, should call wrapped again
      expect(adapter.get_key('c1')).to eq(k)
      expect(wrapped.get_key_calls).to eq(2)
    end
  end

  describe 'delegation' do
    it 'delegates to wrapped adapter for existing methods' do
      expect(adapter.respond_to?(:existing)).to be(true)
      expect(adapter.existing).to eq(:existing_called)
    end
  end
end
