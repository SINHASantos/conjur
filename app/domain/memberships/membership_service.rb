# frozen_string_literal: true

require 'singleton'

module Memberships
  class MembershipService
    include Singleton
    include Domain
    include Logging

    GROUP_DEPTH_LIMIT = 5

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

    def add_member(role, account, group_identifier, member)
      log_debug({ role: role, account: account, group_identifier: group_identifier, member: member })
      check_group_is_not_own_member(group_identifier, member)

      group_res = @res_service.read_res(role, account, 'group', group_identifier)
      member_res = read_member_res(role, account, member)
      check_membership_not_exist(group_res, member_res)

      membership_db = create_membership_db(group_res, member_res)
      Memberships::Member.from_model(membership_db)
    rescue => e
      @logger.error("Failed to add member: #{e.message}")
      raise e
    end

    def remove_member(role, account, group_identifier, member)
      log_debug({ role: role, account: account, group_identifier: group_identifier, member: member })

      group_res = @res_service.read_res(role, account, 'group', group_identifier)
      member_res = read_member_res(role, account, member)
      membership_db = fetch_membership_db(group_res, member_res)
      if membership_db.nil?
        raise Errors::Group::ResourceNotMember.new(member.id, member.kind, domain_id(group_identifier))
      end

      membership_db.destroy
      Memberships::Member.from_model(membership_db)
    end

    def check_membership_not_exist(group_res, member_res)
      membership = fetch_membership_db(group_res, member_res)
      return if membership.nil?

      raise Errors::Group::DuplicateMember.new(domain_id(identifier(member_res.id)), kind(member_res.id), group_res.id)
    end

    def create_membership_db(group_res, member_res, skip_depth_check: false)
      db_object = @role_membership_repo.create(
        role_id: group_res.resource_id,
        member_id: member_res.resource_id,
        admin_option: false,
        ownership: false,
        policy_id: group_res.policy_id
      )

      unless skip_depth_check
        chain_depth = db_object.longest_membership_chain(GROUP_DEPTH_LIMIT + 1)
        if chain_depth > GROUP_DEPTH_LIMIT
          raise ApplicationController::UnprocessableContent.new(
            "Adding member #{member_res.resource_id} into group #{group_res.resource_id} " \
            "exceeds depth limit of #{GROUP_DEPTH_LIMIT} or forms a cycle."
          )
        end
      end

      db_object
    end

    private

    def read_member_res(role, account, member)
      @res_service.read_res(role, account, member.kind, member.id)
    rescue Exceptions::RecordNotFound => e
      raise ApplicationController::InvalidParameter, e.message
    end

    def check_group_is_not_own_member(group_identifier, member)
      return unless member.kind == "group"

      normalized_identifier = group_identifier.start_with?("/") ? group_identifier : "/#{group_identifier}"
      normalized_member_id  = member.id.start_with?("/")        ? member.id        : "/#{member.id}"

      if normalized_identifier == normalized_member_id
        raise Errors::Conjur::ParameterValueInvalid.new(
          "Member ID",
          "The '#{normalized_identifier}' group cannot be a member of itself"
        )
      end
    end

    def fetch_membership_db(group_res, member_res)
      @role_membership_repo.where(
        role_id: group_res.resource_id,
        member_id: member_res.resource_id,
        ownership: false
      ).first
    end
  end
end
