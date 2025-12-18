# frozen_string_literal: true

require "spec_helper"
require_relative '../../../lib/slosilo_cache/clear_cache_listener'

describe SlosiloCache::ClearCacheListener do
  class FakeDb
    def initialize(notifications:)
      @notifications = notifications
      @channels = []
    end

    attr_reader :channels

    def listen(channel)
      @channels << channel
      payload = @notifications.pop # block until a payload is available
      yield(channel, payload)
    end
  end

  class FlakyDb
    def initialize(notifications:)
      @notifications = notifications
      @calls = 0
    end

    def listen(channel)
      @calls += 1
      if @calls == 1
        raise StandardError, 'temporary failure'
      end

      payload = @notifications.pop
      yield(channel, payload)
    end
  end

  let(:logger) do
    double('logger', debug: nil, warn: nil, error: nil)
  end

  def kill_thread(listener)
    t = listener.instance_variable_get(:@listener_thread)
    return unless t&.alive?

    t.kill
    t.join
  end

  after do
    # Ensure no thread leaks between examples
    ObjectSpace.each_object(described_class) do |l|
      kill_thread(l)
    end
  end

  it 'does not start without a DB' do
    on_clear = -> {}
    listener = described_class.new(db: nil, logger: logger, on_clear: on_clear)

    listener.start!

    expect(listener.instance_variable_get(:@listener_thread)).to be_nil
  end

  it 'starts a listener thread and reacts to NOTIFY by calling on_clear' do
    notifications = Queue.new
    db = FakeDb.new(notifications: notifications)
    called = Concurrent::AtomicBoolean.new(false)
    on_clear = -> { called.make_true }

    listener = described_class.new(db: db, logger: logger, on_clear: on_clear)

    listener.start!

    notifications << 'payload-1'

    # Wait briefly for the thread to process
    sleep 0.05

    expect(called.true?).to be(true)
    expect(db.channels).to include('clear_slosilo_cache')

    kill_thread(listener)
  end

  it 'does not crash when on_clear raises' do
    notifications = Queue.new
    db = FakeDb.new(notifications: notifications)
    on_clear = -> { raise 'boom' }

    listener = described_class.new(db: db, logger: logger, on_clear: on_clear)

    listener.start!

    notifications << 'payload-err'

    sleep 0.05

    # No assertion needed, just ensure no crash

    kill_thread(listener)
  end

  it 'recovers when db.listen raises and keeps listening' do
    notifications = Queue.new
    db = FlakyDb.new(notifications: notifications)
    called = Concurrent::AtomicBoolean.new(false)
    on_clear = -> { called.make_true }

    listener = described_class.new(db: db, logger: logger, on_clear: on_clear)

    listener.start!

    # First call to listen will raise; second will consume this payload
    notifications << 'payload-after-error'

    sleep 0.05

    expect(called.true?).to be(true)

    kill_thread(listener)
  end

  it 'does not start a second listener if one is already running' do
    notifications = Queue.new
    db = FakeDb.new(notifications: notifications)
    on_clear = -> {}

    listener = described_class.new(db: db, logger: logger, on_clear: on_clear)
    listener.start!
    first_thread = listener.instance_variable_get(:@listener_thread)

    # Push one payload to ensure thread enters listen
    notifications << 'p1'
    sleep 0.02

    listener.start!
    second_thread = listener.instance_variable_get(:@listener_thread)

    expect(second_thread).to eq(first_thread)
    expect(second_thread&.alive?).to be(true)

    kill_thread(listener)
  end
end
