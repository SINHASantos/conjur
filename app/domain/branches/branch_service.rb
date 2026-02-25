# frozen_string_literal: true

require 'singleton'

module Branches
  class BranchService
    include Singleton
    include Domain
    include Logging

    # rubocop:disable Metrics/ParameterLists
    def initialize(
      owner_service: Branches::OwnerService.instance,
      annotation_service: Annotations::AnnotationService.instance,
      res_service: Resources::ResourceService.instance,
      res_scopes_service: Resources::ResourceScopesService.instance,
      role_repo: ::Role,
      role_membership_repo: ::RoleMembership,
      secret_repo: ::Secret,
      logger: Rails.logger
    )
      @owner_service = owner_service
      @annotation_service = annotation_service
      @res_service = res_service
      @res_scopes_service = res_scopes_service
      @role_repo = role_repo
      @role_membership_repo = role_membership_repo
      @secret_repo = secret_repo
      @logger = logger
    end
    # rubocop:enable Metrics/ParameterLists

    def check_branch_exists(account, identifier)
      @res_service.check_exists(account, 'policy', identifier, 'branch')
    end

    def read_branch(role, account, identifier)
      policy = @res_service.read_res(role, account, 'policy', identifier)
      Branch.from_model(policy)
    rescue Exceptions::Forbidden, Exceptions::RecordNotFound
      raise Exceptions::RecordNotFound, full_id(account, 'branch', identifier)
    end

    def get_branch(account, identifier)
      policy = @res_service.get_res(account, 'policy', identifier)
      Branch.from_model(policy)
    rescue Exceptions::RecordNotFound
      raise Exceptions::RecordNotFound, full_id(account, 'branch', identifier)
    end

    def fetch_branch(account, identifier)
      policy = @res_service.fetch_res(account, 'policy', identifier)
      Branch.from_model(policy) unless policy.nil?
    end

    def check_parent_branch_exists(account, identifier)
      log_debug(account:, identifier:)

      return if root?(identifier)

      check_branch_exists(account, parent_of(identifier))
    end

    def create_branch(account, branch)
      log_debug(account:, branch:)

      policy_id = full_id(account, 'policy', branch.branch)
      branch_id = full_id(account, 'policy', branch.identifier)
      owner_id = @owner_service.resource_owner_id(account, branch.branch, branch.owner)
      log_debug(policy_id:, branch_id:, owner_id:)

      # policy
      policy = @res_service.save_res(policy_id, owner_id, branch_id)

      # role
      @role_repo.create(role_id: branch_id, policy_id: policy_id).save

      # role memberships
      create_role_membership(policy_id, owner_id, branch_id)

      # annotations
      branch.annotations.each do |a_key, a_value|
        @annotation_service.create_annotation(branch_id, a_key, a_value, policy_id).save
      end

      Branch.from_model(policy)
    end

    def create_role_membership(policy_id, owner_id, branch_id)
      @role_membership_repo.create(
        role_id: branch_id,
        member_id: owner_id,
        policy_id: policy_id,
        admin_option: true, ownership: true
      ).save
    end

    def update_branch(account, branch_up_part, identifier)
      log_debug(account:, branch_up_part:, identifier:)

      policy = @res_service.get_res(account, 'policy', identifier, 'branch')

      update_owner(account, policy, branch_up_part.owner) if branch_up_part.owner.set?
      update_annotations(policy, branch_up_part.annotations) unless branch_up_part.annotations.empty?
      fetch_branch(account, policy.identifier)
    end

    def check_branch_not_conflict(account, identifier)
      log_debug(account:, identifier:)
      return if @res_service.not_exists?(account, 'policy', identifier)

      raise Exceptions::RecordExists.new('Branch', full_id(account, 'branch', identifier))
    end

    def read_branches(role_id, account, paging, identifier)
      log_debug(role_id:, account:, paging:, identifier:)

      base_scope = @res_scopes_service.visible_resources_scope(account, role_id, identifier)
      total_count = base_scope.count

      branches = @res_scopes_service.paginate_scope(paging, base_scope)
                                    .eager(owner: proc { |ds| ds.select(:role_id) })
                                    .eager(:annotations)
                                    .all
                                    .map { |pol| Branch.from_model(pol) }

      # result to be returned
      { branches: branches,
        count: total_count }
    end

    def delete_branch(account, role, identifier)
      log_debug("role.id = #{role.id}", account:, identifier:)

      resources = @res_scopes_service.resources_to_del_scope(account, identifier)
                                     .order(Sequel.lit("length(resource_id)").desc)
                                     .all

      resources.each do |res|
        raise Exceptions::RecordNotFound, full_id(account, res.kind, res.identifier) unless role.allowed_to?(:update, res)

        res.secrets.each(&:delete)
        res.annotations.each(&:delete)
        res.destroy
        @role_repo[res.id]&.destroy
      end
    end

    private

    def update_annotations(policy, annotations)
      log_debug(policy:, annotations:)

      merged_annotations = get_saved_annotations(policy).merge(annotations)
      log_debug(merged_annotations:)

      annotations.each do |ann_key, ann_value|
        @annotation_service.upsert_annotation(policy.id, policy.policy_id, ann_key, ann_value)
      end
    end

    def get_saved_annotations(policy)
      Annotations::Annotations.from_model(policy.annotations)
                              .to_h
                              .deep_transform_keys(&:to_sym)
    end

    def update_owner(account, policy, owner)
      log_debug(account:, policy:, owner:)

      parent = parent_of(policy.identifier)
      owner_id = @owner_service.resource_owner_id(account, parent, owner)
      log_debug(parent:, owner_id:)

      policy.update(owner_id: owner_id).save
    end
  end
end
