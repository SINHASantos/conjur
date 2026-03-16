# frozen_string_literal: true

require 'singleton'
require_relative '../domain'

module Authorisation
  class AuthorisationService
    include Singleton
    include Domain
    include Logging

    def initialize(
      *args,
      db: Sequel::Model.db,
      logger: Rails.logger,

      **kwargs
    )
      super(*args, **kwargs)
      @db = db
      @logger = logger
    end

    def auth_create_or_up_in_branch(role, account, identifier)
      auth_create_or_up(role, account, 'policy', identifier, 'branch')
    end

    def auth_create_or_up(role, account, kind, identifier, kind_for_error = nil)
      auth_any_actions(role, %i[create update], account, kind, identifier, kind_for_error)
    end

    def auth_any_actions(role, actions, account, kind, identifier, kind_for_error = nil)
      res_id = full_id(account, kind, identifier)
      can_any_action = false
      actions.each do |action|
        can_any_action ||= can_action?(role, action, res_id)
      end
      return true if can_any_action

      raise Exceptions::RecordNotFound, full_id(account, kind_for_error || kind, identifier)
    end

    def auth_action(role, action, account, kind, identifier, kind_for_error = nil)
      res_id = full_id(account, kind, identifier)
      return true if can_action?(role, action, res_id)

      raise Exceptions::RecordNotFound, full_id(account, kind_for_error || kind, identifier)
    end

    def can_action?(role, action, res_id)
      visible_to?(role.id, res_id) && role.check_allowed_to?(action, res_id)
    end

    def visible_to?(role_id, res_id)
      !@db.select(Sequel.function(:is_resource_visible, res_id, role_id)).single_value.nil?
    end
  end
end