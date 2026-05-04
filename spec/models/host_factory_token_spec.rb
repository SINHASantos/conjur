# frozen_string_literal: true

require 'spec_helper'

describe HostFactoryToken do
  include_context "create user"

  let(:login) { "the-user" }

  around(:each) do |example|
    Sequel::Model.db.transaction do
      example.run
      raise Sequel::Rollback
    end
  end

  before do
    layer_p = Conjur::PolicyParser::Types::Layer.new("the-layer")
    layer_p.owner = Conjur::PolicyParser::Types::Role.new(the_user.id)
    layer_p.account = "rspec"

    hf_p = Conjur::PolicyParser::Types::HostFactory.new("the-factory")
    hf_p.account = "rspec"
    hf_p.owner = Conjur::PolicyParser::Types::Role.new(the_user.id)
    hf_p.layers = []
    hf_p.layers << layer_p

    [layer_p, hf_p].each do |obj|
      Loader::Types.wrap(obj).create!
    end
  end

  let(:host_factory) { Resource["rspec:host_factory:the-factory"] }

  let(:token) do
    HostFactoryToken.create(
      resource: host_factory,
      expiration: 1.hour.from_now,
      cidr: []
    )
  end

  describe '.random_token' do
    it "generates a non-empty string" do
      t = HostFactoryToken.random_token
      expect(t).to be_a(String)
      expect(t).not_to be_empty
    end

    it "generates unique tokens" do
      tokens = Array.new(5) { HostFactoryToken.random_token }
      expect(tokens.uniq.length).to eq(5)
    end
  end

  describe '.from_token' do
    it "finds a token by its plaintext value" do
      plaintext = token.token
      found = HostFactoryToken.from_token(plaintext)
      expect(found).to eq(token)
    end

    it "returns nil for an unknown token" do
      expect(HostFactoryToken.from_token("nonexistent")).to be_nil
    end
  end

  describe '#as_json' do
    it "excludes sensitive fields and formats expiration and cidr" do
      json = token.as_json
      expect(json).not_to have_key(:token)
      expect(json).not_to have_key(:token_sha256)
      expect(json).not_to have_key(:resource_id)
      expect(json[:expiration]).to match(/\d{4}-\d{2}-\d{2}T/)
      expect(json[:cidr]).to eq([])
    end

    it "formats cidr entries as strings" do
      t = HostFactoryToken.create(
        resource: host_factory,
        expiration: 1.hour.from_now,
        cidr: ["192.168.1.0/24"]
      )
      expect(t.as_json[:cidr]).to eq(["192.168.1.0/24"])
    end
  end

  describe '#as_creation_json' do
    it "includes the plaintext token" do
      json = token.as_creation_json
      expect(json[:token]).to eq(token.token)
    end
  end

  describe '#valid?' do
    it "returns true for a non-expired token with no origin" do
      expect(token.valid?).to be(true)
    end

    it "returns false for an expired token" do
      expired_token = HostFactoryToken.create(
        resource: host_factory,
        expiration: 1.hour.ago,
        cidr: []
      )
      expect(expired_token.valid?).to be(false)
    end

    context "with origin" do
      let(:cidr_token) do
        HostFactoryToken.create(
          resource: host_factory,
          expiration: 1.hour.from_now,
          cidr: ["10.0.0.0/8"]
        )
      end

      it "returns true when origin matches cidr" do
        expect(cidr_token.valid?(origin: "10.1.2.3")).to be(true)
      end

      it "returns false when origin does not match cidr" do
        expect(cidr_token.valid?(origin: "192.168.1.1")).to be(false)
      end
    end
  end

  describe '#valid_origin?' do
    it "returns true when cidr is empty" do
      expect(token.valid_origin?("1.2.3.4")).to be(true)
    end

    it "returns true when ip is within cidr" do
      t = HostFactoryToken.create(
        resource: host_factory,
        expiration: 1.hour.from_now,
        cidr: ["192.168.0.0/16"]
      )
      expect(t.valid_origin?("192.168.1.1")).to be(true)
    end

    it "returns false when ip is outside cidr" do
      t = HostFactoryToken.create(
        resource: host_factory,
        expiration: 1.hour.from_now,
        cidr: ["192.168.0.0/16"]
      )
      expect(t.valid_origin?("10.0.0.1")).to be(false)
    end
  end

  describe '#expired?' do
    it "returns false for a future expiration" do
      expect(token.expired?).to be(false)
    end

    it "returns true for a past expiration" do
      expired_token = HostFactoryToken.create(
        resource: host_factory,
        expiration: 1.hour.ago,
        cidr: []
      )
      expect(expired_token.expired?).to be(true)
    end
  end

  describe '#validate' do
    it "requires expiration" do
      expect do
        HostFactoryToken.create(
          resource: host_factory,
          cidr: []
        )
      end.to raise_error(Sequel::ValidationFailed, /expiration/)
    end
  end

  describe '#before_create' do
    it "auto-generates token and token_sha256" do
      t = HostFactoryToken.create(
        resource: host_factory,
        expiration: 1.hour.from_now,
        cidr: []
      )
      expect(t.token).not_to be_nil
      expect(t.token_sha256).to eq(Digest::SHA256.hexdigest(t.token))
    end
  end
end
