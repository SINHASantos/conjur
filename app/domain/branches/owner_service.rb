# frozen_string_literal: true

require 'singleton'

module Branches
  class OwnerService
    include Singleton
    include Domain
    include Logging

    def initialize(
      role_repository: ::Role,
      logger: Rails.logger
    )
      @role_repository = role_repository
      @logger = logger
    end

    def resource_owner(parent_identifier, owner)
      log_debug("parent_identifier = #{parent_identifier}, owner = #{owner}")

      return owner if owner.set?

      Owner.new(**{ kind: root?(parent_identifier) ? 'user' : 'policy',
                    id: root?(parent_identifier) ? 'admin' : parent_identifier })
    end

    def resource_owner_id(account, parent_identifier, owner)
      res_owner = resource_owner(parent_identifier, owner)
      full_id(account, res_owner.kind, res_owner.id)
    end

    def check_owner_exists(account, owner)
      log_debug("account = #{account}, owner = #{owner}")

      role_id = full_id(account, owner.kind, owner.id)
      log_debug("role_id = #{role_id}")

      role = @role_repository[role_id]
      log_debug("role = #{role}")

      return owner unless role.nil?

      raise Exceptions::RecordNotFound, role_id
    end
  end
end
