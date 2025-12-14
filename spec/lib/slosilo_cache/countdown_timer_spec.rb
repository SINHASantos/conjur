# frozen_string_literal: true

require "spec_helper"
require_relative "../../../lib/slosilo_cache/countdown_timer"

describe SlosiloCache::CountdownTimer do
  it "treats nil or zero duration as passed" do
    expect(described_class.new(nil).passed?).to be(true)
    expect(described_class.new(0).passed?).to be(true)
  end

  it "raises for negative duration" do
    expect { described_class.new(-1) }.to raise_error(ArgumentError, /non-negative/)
  end

  it "returns not passed first, then passed when now advances beyond duration" do
    calls = 0
    now = lambda {
      calls += 1
      case calls
      when 1 then 100.0  # initialization
      when 2 then 100.0  # first check: same time -> not passed
      else 120.0         # later: advanced -> passed
      end
    }

    timer = described_class.new(10.0, now)
    expect(timer.passed?).to be(false) # first check at 100.0
    expect(timer.passed?).to be(true)  # next check at 120.0
  end

  it "reset restarts countdown from current time" do
    calls = 0
    now = lambda {
      calls += 1
      case calls
      when 1 then 200.0  # initialization
      when 2 then 200.0  # before reset: not passed
      when 3 then 205.0  # reset sets start to 205.0
      when 4 then 214.0  # after reset: 9s elapsed -> not passed
      else 216.0         # after reset: 11s elapsed -> passed
      end
    }

    timer = described_class.new(10.0, now)
    expect(timer.passed?).to be(false) # at start
    timer.reset
    expect(timer.passed?).to be(false) # 9s after reset
    expect(timer.passed?).to be(true)  # 11s after reset (>10s)
  end
end
