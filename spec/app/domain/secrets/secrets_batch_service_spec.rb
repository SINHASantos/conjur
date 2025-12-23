# frozen_string_literal: true

require 'spec_helper'

describe Secrets::SecretsBatchService do
  let(:role) { instance_double(Role, id: 'rspec:user:alice') }
  let(:account) { 'rspec' }
  let(:logger) { Rails.logger }
  let(:secret_repo) { class_double('Secret') }
  let(:db) { instance_double(Sequel::Database) }
  let(:service) { described_class.instance }
  let(:batch) { Secrets::SecretsBatch.new(ids: ids, encode_values: encode_values) }
  let(:encode_values) { '' }
  let(:ids) { %w[data/var1 data/var2] }

  around do |example|
    # Reset singleton before and after each test
    described_class.instance_variable_set(:@singleton__instance__, nil)
    example.run
    described_class.instance_variable_set(:@singleton__instance__, nil)
  end

  before do
    # Mock Sequel::Model.db to return our test double
    allow(Sequel::Model).to receive(:db).and_return(db)
    allow(Sequel).to receive(:pg_array).and_call_original
  end
  def enc(val, aad:)
    allow(Slosilo::EncryptedAttributes).to receive(:decrypt).with(val, aad: aad).and_return(val.dup)
    val
  end

  describe '#read_batch' do
    context 'with successful requests' do
      it 'returns 200 with raw UTF-8 values for valid secrets' do
        fetch_rows = [
          {
            id: "#{account}:variable:data/var1",
            not_present: false,
            no_var: false,
            cannot_read: false,
            cannot_exec: false,
            value: enc('secret_value1', aad: "#{account}:variable:data/var1"),
            expires_at: nil
          },
          {
            id: "#{account}:variable:data/var2",
            not_present: false,
            no_var: false,
            cannot_read: false,
            cannot_exec: false,
            value: enc('secret_value2', aad: "#{account}:variable:data/var2"),
            expires_at: Time.now
          }
        ]

        expect(db).to receive(:fetch).and_return(double(all: fetch_rows))
        result = service.read_batch(role, account, batch)

        expect(result[:secrets].length).to eq(2)
        expect(result[:secrets][0][:id]).to eq('data/var1')
        expect(result[:secrets][0][:status]).to eq(200)
        expect(result[:secrets][0][:value]).to eq('secret_value1')
        expect(result[:secrets][0][:expires_at]).to be_nil
        expect(result[:secrets][1][:id]).to eq('data/var2')
        expect(result[:secrets][1][:status]).to eq(200)
        expect(result[:secrets][1][:value]).to eq('secret_value2')
        expect(result[:secrets][1][:expires_at]).to be_a(Time)
      end

      it 'returns base64 encoded values when encode_values=base64' do
        batch64 = Secrets::SecretsBatch.new(ids: %w[data/var1], encode_values: Secrets::SecretsBatch::BASE_64)
        row = {
          id: "#{account}:variable:data/var1",
          not_present: false,
          no_var: false,
          cannot_read: false,
          cannot_exec: false,
          value: enc('secret_value1', aad: "#{account}:variable:data/var1"),
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, batch64)
        expect(result[:secrets].first[:status]).to eq(200)
        expect(result[:secrets].first[:value]).to eq(Base64.strict_encode64('secret_value1'))
      end

      it 'handles binary data correctly with force_encoding UTF-8' do
        binary_data = "\xC0\xFF\xEE".dup.force_encoding('ASCII-8BIT')
        row = {
          id: "#{account}:variable:data/binary",
          not_present: false,
          no_var: false,
          cannot_read: false,
          cannot_exec: false,
          value: enc(binary_data, aad: "#{account}:variable:data/binary"),
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/binary]))
        expect(result[:secrets].first[:status]).to eq(200)
        expect(result[:secrets].first[:value].encoding).to eq(Encoding::UTF_8)
      end

      it 'passes correct parameters to SQL query' do
        rows = [
          { id: "#{account}:variable:data/var1", not_present: false, no_var: false, cannot_read: false, cannot_exec: false, value: enc('v1', aad: "#{account}:variable:data/var1"), expires_at: nil }
        ]
        expect(db).to receive(:fetch) do |sql, pg_ids, rid1, rid2|
          expect(sql).to include('WITH input_ids AS')
          expect(sql).to include('is_role_allowed_to')
          expect(pg_ids).to be_a(Sequel::Postgres::PGArray)
          expect(rid1).to eq(role.id)
          expect(rid2).to eq(role.id)
          double(all: rows)
        end

        service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/var1]))
      end
    end

    context 'with no content (204)' do
      it 'returns 204 when variable exists but has no value' do
        row = {
          id: "#{account}:variable:data/empty",
          not_present: false,
          no_var: true,
          cannot_read: false,
          cannot_exec: false,
          value: nil,
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/empty]))
        expect(result[:secrets].first[:id]).to eq('data/empty')
        expect(result[:secrets].first[:status]).to eq(204)
        expect(result[:secrets].first[:value]).to eq('')
      end

      it 'returns empty string value for 204 status' do
        row = {
          id: "#{account}:variable:data/no_value",
          not_present: false,
          no_var: true,
          cannot_read: false,
          cannot_exec: false,
          value: nil,
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/no_value]))
        expect(result[:secrets].first[:value]).to eq('')
        expect(result[:secrets].first.keys).to include(:id, :status, :value)
      end
    end

    context 'with forbidden access (403)' do
      it 'returns 403 when user cannot execute' do
        row = {
          id: "#{account}:variable:data/noexec",
          not_present: false,
          no_var: false,
          cannot_read: false,
          cannot_exec: true,
          value: enc('secret', aad: "#{account}:variable:data/noexec"),
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/noexec]))
        expect(result[:secrets].first[:id]).to eq('data/noexec')
        expect(result[:secrets].first[:status]).to eq(403)
        expect(result[:secrets].first[:description]).to eq('Forbidden')
        expect(result[:secrets].first).not_to have_key(:value)
      end
    end

    context 'with not found (404)' do
      it 'returns 404 when resource does not exist' do
        row = {
          id: "#{account}:variable:data/notpresent",
          not_present: true,
          no_var: false,
          cannot_read: false,
          cannot_exec: false,
          value: nil,
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/notpresent]))
        expect(result[:secrets].first[:id]).to eq('data/notpresent')
        expect(result[:secrets].first[:status]).to eq(404)
        expect(result[:secrets].first[:description]).to eq('Variable data/notpresent not found')
      end

      it 'returns 404 when user cannot read' do
        row = {
          id: "#{account}:variable:data/noread",
          not_present: false,
          no_var: false,
          cannot_read: true,
          cannot_exec: false,
          value: nil,
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/noread]))
        expect(result[:secrets].first[:status]).to eq(404)
        expect(result[:secrets].first[:description]).to eq('Variable data/noread not found')
      end

      it 'returns 404 for conjur/* branch variables' do
        row = {
          id: "#{account}:variable:conjur/prohibited",
          not_present: false,
          no_var: false,
          cannot_read: false,
          cannot_exec: false,
          value: enc('whatever', aad: "#{account}:variable:conjur/prohibited"),
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[conjur/prohibited]))
        expect(result[:secrets].first[:id]).to eq('conjur/prohibited')
        expect(result[:secrets].first[:status]).to eq(404)
        expect(result[:secrets].first[:description]).to eq('Variable conjur/prohibited not found')
      end

      it 'handles multiple not found scenarios' do
        rows = [
          {
            id: "#{account}:variable:data/notpresent",
            not_present: true,
            no_var: false,
            cannot_read: false,
            cannot_exec: false,
            value: nil,
            expires_at: nil
          },
          {
            id: "#{account}:variable:data/noread",
            not_present: false,
            no_var: false,
            cannot_read: true,
            cannot_exec: false,
            value: nil,
            expires_at: nil
          }
        ]
        expect(db).to receive(:fetch).and_return(double(all: rows))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/notpresent data/noread]))
        expect(result[:secrets][0][:status]).to eq(404)
        expect(result[:secrets][0][:description]).to eq('Variable data/notpresent not found')
        expect(result[:secrets][1][:status]).to eq(404)
        expect(result[:secrets][1][:description]).to eq('Variable data/noread not found')
      end
    end

    context 'with mixed statuses' do
      it 'returns correct statuses for mixed permission scenarios' do
        rows = [
          {
            id: "#{account}:variable:data/ok",
            not_present: false,
            no_var: false,
            cannot_read: false,
            cannot_exec: false,
            value: enc('value', aad: "#{account}:variable:data/ok"),
            expires_at: nil
          },
          {
            id: "#{account}:variable:data/empty",
            not_present: false,
            no_var: true,
            cannot_read: false,
            cannot_exec: false,
            value: nil,
            expires_at: nil
          },
          {
            id: "#{account}:variable:data/forbidden",
            not_present: false,
            no_var: false,
            cannot_read: false,
            cannot_exec: true,
            value: enc('secret', aad: "#{account}:variable:data/forbidden"),
            expires_at: nil
          },
          {
            id: "#{account}:variable:data/missing",
            not_present: true,
            no_var: false,
            cannot_read: false,
            cannot_exec: false,
            value: nil,
            expires_at: nil
          }
        ]
        expect(db).to receive(:fetch).and_return(double(all: rows))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/ok data/empty data/forbidden data/missing]))
        expect(result[:secrets][0][:status]).to eq(200)
        expect(result[:secrets][1][:status]).to eq(204)
        expect(result[:secrets][2][:status]).to eq(403)
        expect(result[:secrets][3][:status]).to eq(404)
      end
    end

    context 'with empty or nil values' do
      it 'handles empty string values' do
        row = {
          id: "#{account}:variable:data/empty_string",
          not_present: false,
          no_var: false,
          cannot_read: false,
          cannot_exec: false,
          value: enc('', aad: "#{account}:variable:data/empty_string"),
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/empty_string]))
        expect(result[:secrets].first[:status]).to eq(200)
        expect(result[:secrets].first[:value]).to eq('')
      end

      it 'handles nil values as empty string' do
        row = {
          id: "#{account}:variable:data/nil_value",
          not_present: false,
          no_var: false,
          cannot_read: false,
          cannot_exec: false,
          value: nil,
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))
        allow(Slosilo::EncryptedAttributes).to receive(:decrypt).with(nil, aad: anything).and_return(nil)

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/nil_value]))
        expect(result[:secrets].first[:value]).to eq('')
      end
    end

    context 'with identifier extraction' do
      it 'correctly extracts identifier from full resource ID' do
        row = {
          id: "#{account}:variable:data/path/to/var",
          not_present: false,
          no_var: false,
          cannot_read: false,
          cannot_exec: false,
          value: enc('value', aad: "#{account}:variable:data/path/to/var"),
          expires_at: nil
        }
        expect(db).to receive(:fetch).and_return(double(all: [row]))

        result = service.read_batch(role, account, Secrets::SecretsBatch.new(ids: %w[data/path/to/var]))
        expect(result[:secrets].first[:id]).to eq('data/path/to/var')
      end
    end
  end
end
