# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Authorisation::AuthorisationService do
  let(:db) { instance_double('Sequel::Database') }
  let(:logger) { instance_double('Logger', debug?: false, debug: nil, error: nil) }

  let(:service) do
    described_class.send(:new, db: db, logger: logger)
  end

  let(:role) { instance_double('Role', id: 'rspec:user:admin') }
  let(:account) { 'rspec' }
  let(:kind) { 'policy' }
  let(:identifier) { 'data/branch1' }
  let(:res_id) { 'rspec:policy:data/branch1' }

  describe '#auth_create_or_up_in_branch' do
    it 'authorizes create or update for policy branch' do
      expect(service).to receive(:auth_create_or_up)
        .with(role, account, 'policy', identifier, 'branch')

      service.auth_create_or_up_in_branch(role, account, identifier)
    end
  end

  describe '#auth_create_or_up' do
    it 'authorizes create or update actions' do
      expect(service).to receive(:auth_any_actions)
        .with(role, %i[create update], account, kind, identifier, nil)

      service.auth_create_or_up(role, account, kind, identifier)
    end
  end

  describe '#auth_any_actions' do
    it 'returns true when at least one action is allowed' do
      allow(service).to receive(:can_action?).with(role, :create, res_id).and_return(false)
      allow(service).to receive(:can_action?).with(role, :update, res_id).and_return(true)

      result = service.auth_any_actions(role, %i[create update], account, kind, identifier)

      expect(result).to be true
    end

    it 'raises RecordNotFound when no action is allowed' do
      allow(service).to receive(:can_action?).with(role, :create, res_id).and_return(false)
      allow(service).to receive(:can_action?).with(role, :update, res_id).and_return(false)

      expect do
        service.auth_any_actions(role, %i[create update], account, kind, identifier)
      end.to raise_error(Exceptions::RecordNotFound, "Policy 'data/branch1' not found in account 'rspec'")
    end

    it 'uses kind_for_error when provided' do
      allow(service).to receive(:can_action?).with(role, :create, res_id).and_return(false)

      expect do
        service.auth_any_actions(role, [:create], account, kind, identifier, 'branch')
      end.to raise_error(Exceptions::RecordNotFound, "Branch 'data/branch1' not found in account 'rspec'")
    end
  end

  describe '#auth_action' do
    it 'returns true when action is allowed' do
      allow(service).to receive(:can_action?).with(role, :read, res_id).and_return(true)

      expect(service.auth_action(role, :read, account, kind, identifier)).to be true
    end

    it 'raises RecordNotFound when action is not allowed' do
      allow(service).to receive(:can_action?).with(role, :read, res_id).and_return(false)

      expect do
        service.auth_action(role, :read, account, kind, identifier)
      end.to raise_error(Exceptions::RecordNotFound, "Policy 'data/branch1' not found in account 'rspec'")
    end

    it 'raises with kind_for_error when provided' do
      allow(service).to receive(:can_action?).with(role, :update, res_id).and_return(false)

      expect do
        service.auth_action(role, :update, account, kind, identifier, 'branch')
      end.to raise_error(Exceptions::RecordNotFound, "Branch 'data/branch1' not found in account 'rspec'")
    end
  end

  describe '#can_action?' do
    it 'returns true when resource is visible and action is allowed' do
      allow(service).to receive(:visible_to?).with(role.id, res_id).and_return(true)
      allow(role).to receive(:check_allowed_to?).with(:read, res_id).and_return(true)

      expect(service.can_action?(role, :read, res_id)).to be true
    end

    it 'returns false when resource is not visible' do
      allow(service).to receive(:visible_to?).with(role.id, res_id).and_return(false)

      expect(service.can_action?(role, :read, res_id)).to be false
    end

    it 'returns false when action is not allowed' do
      allow(service).to receive(:visible_to?).with(role.id, res_id).and_return(true)
      allow(role).to receive(:check_allowed_to?).with(:read, res_id).and_return(false)

      expect(service.can_action?(role, :read, res_id)).to be false
    end
  end

  describe '#visible_to?' do
    let(:dataset) { instance_double('Sequel::Dataset') }

    it 'returns true when visibility function returns a value' do
      expect(db).to receive(:select).and_return(dataset)
      expect(dataset).to receive(:single_value).and_return('visible')

      expect(service.visible_to?(role.id, res_id)).to be true
    end

    it 'returns false when visibility function returns nil' do
      expect(db).to receive(:select).and_return(dataset)
      expect(dataset).to receive(:single_value).and_return(nil)

      expect(service.visible_to?(role.id, res_id)).to be false
    end
  end
end

