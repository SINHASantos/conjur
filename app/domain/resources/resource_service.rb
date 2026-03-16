# frozen_string_literal: true

require 'singleton'

module Resources
  class ResourceService
    include Singleton
    include Domain
    include Logging

    def initialize(
      res_repo: ::Resource,
      role_repo: ::Role,
      auth_service: Authorisation::AuthorisationService.instance,
      logger: Rails.logger
    )
      @res_repo = res_repo
      @role_repo = role_repo
      @auth_service = auth_service
      @logger = logger
    end

    def save_res(policy_id, owner_id, resource_id, kind_msg: nil)
      @res_repo.create(
        resource_id: resource_id,
        owner_id: owner_id,
        policy_id: policy_id
      ).save
    rescue Sequel::UniqueConstraintViolation
      kind = kind_msg || kind(resource_id)
      identifier = domain_id(identifier(resource_id))
      raise Exceptions::RecordExists.new(kind, identifier)
    end

    def not_exists?(account, kind, identifier)
      res_id = full_id(account, kind, res_identifier(identifier))
      # Existence probe: fetches only a single constant from at most one row.
      @res_repo.where(resource_id: res_id).get(Sequel.lit('1')).nil?
    end

    def exists?(account, kind, identifier)
      !not_exists?(account, kind, identifier)
    end

    def check_exists(account, kind, identifier, kind_for_error = nil)
      log_debug(account:, kind:, identifier:, kind_for_error:)
      log_debug(account:, kind:, identifier:, kind_for_error:)
      return if exists?(account, kind, identifier)

      raise Exceptions::RecordNotFound, full_id(account, kind_for_error || kind, domain_id(identifier))
    end

    # Fetching a resource by id and checking its visibility to the given role
    # @raise Exceptions::RecordNotFound if nil or not visible
    # @return ::Resource
    def read_res(role, account, kind, identifier, kind_for_error = nil)
      resource = fetch_res(account, kind, identifier)
      return resource if resource&.visible_to?(role)

      raise Exceptions::RecordNotFound, full_id(account, kind_for_error || kind, identifier)
    end

    # Fetching a resource by id and checking its nullability
    # @raise Exceptions::RecordNotFound if nil
    # @return ::Resource
    def get_res(account, kind, identifier, kind_for_error = nil)
      resource = fetch_res(account, kind, identifier)
      return resource unless resource.nil?

      raise Exceptions::RecordNotFound, full_id(account, kind_for_error || kind, identifier)
    end

    # Fetching a resource by id - can return nil if not found
    # @return ::Resource or nil
    def fetch_res(account, kind, identifier)
      resource_id = full_id(account, kind, res_identifier(identifier))
      Resource[resource_id]
    end

    # Fetch a resource by its full ID
    # @param resource_id [String] Full resource ID
    # @return [Resource, nil] Resource or nil if not found
    def fetch_by_id(resource_id)
      @res_repo[resource_id]
    end

    def check_res_not_conflict(account, kind, identifier)
      resource = fetch_res(account, kind, identifier)

      raise Exceptions::RecordExists.new(kind, identifier) if resource
    end

    # Find all resources owned by a given resource
    # @param owner_id [String] Full resource ID of the owner
    # @return [Array<Resource>] Array of owned resources
    def find_owned_resources(owner_id)
      @res_repo.where(owner_id: owner_id).all
    end

    # Delete a resource by its full ID
    # @param resource_id [String] Full resource ID
    def delete_resource(resource_id)
      resource = @res_repo[resource_id]
      resource&.destroy
    end
  end
end
