# frozen_string_literal: true

module Authentication
  class RoleIdentifier
    attr_reader :identifier, :attributes

    def initialize(identifier:, attributes: {})
      @identifier = identifier
      @attributes = attributes
    end

    def type
      @identifier.split(':')[1]
    end

    def account
      @identifier.split(':')[0]
    end

    # Role identifier within the account and type context:
    # <account>:<type>:<id>
    def id
      @identifier.split(':')[2]
    end

    def role_for_error
      type == 'host' ? "host/#{id}" : id
    end
  end
end
