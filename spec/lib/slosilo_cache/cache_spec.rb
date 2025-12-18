# frozen_string_literal: true

require 'spec_helper'
require 'concurrent/map'
require_relative '../../../lib/slosilo_cache/cache'

describe SlosiloCache::Cache do
  let(:db) do
    Class.new do
      attr_accessor :in_tx, :commit_hooks, :rollback_hooks

      def initialize
        @in_tx = false
        @commit_hooks = []
        @rollback_hooks = []
      end

      def in_transaction?
        @in_tx
      end

      def after_commit(&blk)
        @commit_hooks << blk
      end

      def after_rollback(&blk)
        @rollback_hooks << blk
      end

      def trigger_commit
        @commit_hooks.each(&:call)
      end

      def trigger_rollback
        @rollback_hooks.each(&:call)
      end

      def listen(channel)
        if block_given?
          yield(channel, nil)
        end
        loop { sleep(0.1) }
      end

      def run(*); end
    end.new
  end

  let(:timer) do
    Class.new do
      attr_accessor :passed_called, :reset_called, :passed_value

      def initialize
        @passed_called = 0
        @reset_called = 0
        @passed_value = false
      end

      def passed?
        @passed_called += 1
        @passed_value
      end

      def reset
        @reset_called += 1
      end
    end.new
  end

  let(:logger) do
    Class.new do
      def info(*); end
      def debug(*); end
      def error(*); end
    end.new
  end

  # No-op listener to avoid starting threads in tests
  let(:noop_listener) do
    Class.new do
      def start!; end
    end.new
  end

  subject(:cache) { described_class.new(db: db, timer: timer, logger: logger, listener: noop_listener) }

  describe '#get and #put outside transaction' do
    before { db.in_tx = false }

    it 'stores in committed cache and returns value' do
      expect(cache.put('id1', 'key1')).to eq('key1')
      expect(cache.get('id1')).to eq('key1')
    end

    it 'misses when not present' do
      expect(cache.get('missing')).to be_nil
    end

    it 'does not register hooks when not in transaction' do
      cache.put('id1', 'key1')
      expect(db.commit_hooks.size).to eq(0)
      expect(db.rollback_hooks.size).to eq(0)
    end
  end

  describe 'time invalidation' do
    before { db.in_tx = false }

    it 'clears committed cache when timer passed' do
      cache.put('id1', 'key1')
      expect(cache.get('id1')).to eq('key1')

      timer.passed_value = true
      # next call should trigger invalidation
      expect(cache.get('id1')).to be_nil
      # timer.reset should have been called once
      expect(timer.reset_called).to eq(1)
    end

    it 'does not clear transactional state or hooks on time invalidation' do
      db.in_tx = true
      cache.put('id1', 'key1') # transactional put registers hooks
      expect(db.commit_hooks.size).to eq(1)
      expect(db.rollback_hooks.size).to eq(1)

      timer.passed_value = true
      # any operation triggers invalidation of committed only
      expect(cache.get('id1')).to eq('key1') # still available in tx cache
      expect(db.commit_hooks.size).to eq(1)
      expect(db.rollback_hooks.size).to eq(1)
    end

    it 'get_by_fingerprint scans caches' do
      # committed
      db.in_tx = false
      k1 = Slosilo::Key.new
      cache.put('idc', k1)
      expect(cache.get_by_fingerprint(k1.fingerprint)).to eq([k1, 'idc'])

      # transactional current thread
      db.in_tx = true
      k2 = Slosilo::Key.new
      cache.put('idt', k2)
      expect(cache.get_by_fingerprint(k2.fingerprint)).to eq([k2, 'idt'])
    end
  end

  describe 'transactional behavior' do
    before { db.in_tx = true }

    it 'stores in per-thread transactional cache when in transaction' do
      expect(cache.put('id1', 'key1')).to eq('key1')
      expect(cache.get('id1')).to eq('key1')
    end

    it 'registers hooks only once per thread even with multiple puts' do
      expect(db.commit_hooks.size).to eq(0)
      expect(db.rollback_hooks.size).to eq(0)

      cache.put('id1', 'key1')
      cache.put('id2', 'key2')
      cache.put('id3', 'key3')

      expect(db.commit_hooks.size).to eq(1)
      expect(db.rollback_hooks.size).to eq(1)
    end

    it 'promotes transactional entries to committed cache on commit and clears tx state' do
      cache.put('id1', 'key1')
      cache.put('id2', 'key2')

      # Before commit: available in tx, not necessarily in committed
      expect(cache.get('id1')).to eq('key1')
      expect(cache.get('id2')).to eq('key2')

      # Simulate commit
      db.trigger_commit

      # After commit hooks, transactional cache for the thread should be cleared
      db.in_tx = false
      expect(cache.get('id1')).to eq('key1')
      expect(cache.get('id2')).to eq('key2')

      # Hooks registration for the thread should be cleared, new tx should re-register
      db.in_tx = true
      cache.put('id3', 'key3')
      expect(db.commit_hooks.size).to eq(2)
      expect(db.rollback_hooks.size).to eq(2)
    end

    it 'drops transactional entries on rollback and does not promote to committed' do
      cache.put('id1', 'key1')

      # Simulate rollback
      db.trigger_rollback

      db.in_tx = false
      expect(cache.get('id1')).to be_nil

      # Hooks registration for the thread should be cleared, new tx should re-register
      db.in_tx = true
      cache.put('id2', 'key2')
      expect(db.commit_hooks.size).to eq(2)
      expect(db.rollback_hooks.size).to eq(2)
    end
  end
end
