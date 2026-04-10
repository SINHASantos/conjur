# frozen_string_literal: true

require 'spec_helper'

describe Responses::Failure do
  context 'when initialized with only a message' do
    let(:failure) { Responses::Failure.new('bar') }

    describe '.message' do
      it 'is the message set in the initializer' do
        expect(failure.message).to eq('bar')
      end
    end

    describe '.level' do
      it 'is at `warn` level by default' do
        expect(failure.level).to eq(:warn)
      end
    end

    describe '.success?' do
      it 'is false' do
        expect(failure.success?).to be(false)
      end
    end

    describe '.bind' do
      it "doesn't bind the response message to the next operation" do
        expect(failure.bind { |response| "foo-#{response}"}).to eq(failure)
      end
    end

    describe '.backtrace' do
      it 'falls back to the construction-site caller stack' do
        expect(failure.backtrace).to be_an(Array)
        expect(failure.backtrace).not_to be_empty
      end
    end
  end

  context 'when initialized with an exception' do
    let(:exception) do
      StandardError.new('boom').tap { |err| err.set_backtrace(['file.rb:1:in test']) }
    end
    let(:failure) { Responses::Failure.new('msg', exception: exception) }

    describe '.backtrace' do
      it 'uses the exception backtrace' do
        expect(failure.backtrace).to eq(exception.backtrace)
      end
    end
  end

  context 'when initialized with an explicit backtrace' do
    let(:explicit_backtrace) { ['explicit.rb:99:in method'] }
    let(:failure) { Responses::Failure.new('msg', backtrace: explicit_backtrace) }

    describe '.backtrace' do
      it 'uses the explicit backtrace' do
        expect(failure.backtrace).to eq(explicit_backtrace)
      end
    end
  end

  context 'when initialized with both an exception and an explicit backtrace' do
    let(:exception) do
      StandardError.new('boom').tap { |err| err.set_backtrace(['exception.rb:1:in test']) }
    end
    let(:explicit_backtrace) { ['explicit.rb:99:in method'] }
    let(:failure) do
      Responses::Failure.new('msg', exception: exception, backtrace: explicit_backtrace)
    end

    describe '.backtrace' do
      it 'prefers the explicit backtrace over the exception backtrace' do
        expect(failure.backtrace).to eq(explicit_backtrace)
      end
    end
  end

  context 'when initialized with all options' do
    let(:message) { 'baz' }
    let(:initialize_arguments) { { level: :debug, status: :forbidden } }
    let(:failure) { Responses::Failure.new(message, **initialize_arguments) }

    describe '.message' do
      context 'when message is set in the initializer' do
        context 'when it is a string' do
          it "is returned as a string" do
            expect(failure.message).to eq('baz')
          end
        end
        context 'when it is a hash' do
          let(:message) { { foo: 'baz' } }
          it 'is returned as a hash' do
            expect(failure.message).to eq({ foo: 'baz' })
          end
        end
        context 'when it is an array' do
          let(:message) { [{ foo: 'baz' }] }
          it 'is returned as an array' do
            expect(failure.message).to eq([{ foo: 'baz' }])
          end
        end
      end
    end

    describe '.to_s' do
      context 'when message is a string' do
        let(:message) { 'baz' }
        it 'returns the expected string' do
          expect(failure.to_s).to eq('baz')
        end
      end
      context 'when message is a hash' do
        let(:message) { { foo: 'baz' } }
        it 'returns the expected string' do
          expect(failure.to_s).to eq('{foo: "baz"}')
        end
      end
      context 'when message is an array' do
        let(:message) { ['baz'] }
        it 'returns the expected string' do
          expect(failure.to_s).to eq('["baz"]')
        end
      end
    end

    describe '.level' do
      context 'when level is a symbol' do
        let(:initialize_arguments) { { level: :warn, status: :forbidden } }
        it 'is the level set in the initializer' do
          expect(failure.level).to eq(:warn)
        end
      end

      context 'when level is a string' do
        let(:initialize_arguments) { { level: 'warn', status: :forbidden } }
        it 'is the level set in the initializer' do
          expect(failure.level).to eq(:warn)
        end
      end
    end

    describe '.status' do
      context 'when set in initializer' do
        it 'is the message set in the initializer' do
          expect(failure.status).to eq(:forbidden)
        end
      end
      context 'when set by default' do
        let(:initialize_arguments) { {} }
        it 'is the default option' do
          expect(failure.status).to eq(:unauthorized)
        end
      end
    end

    describe '.success?' do
      it 'is false' do
        expect(failure.success?).to be(false)
      end
    end
  end
end
