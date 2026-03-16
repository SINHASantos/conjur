# frozen_string_literal: true

class GroupMembershipsController < V2RestController

  def initialize(
    *args,
    membership_service: Memberships::MembershipService.instance,
    **kwargs
  )
    super(*args, **kwargs)

    @membership_service = membership_service
  end

  def create
    url_params = permit_url_params(URL_REQUIRED_PARAMS_IDFR)
    input = permit_body_params(%i[kind id])
    log_debug("url_params = #{url_params}, input = #{input}")

    auth_create(path_identifier)

    member = Memberships::Member.new(**input)
    log_debug("member = #{member}")

    render(json: add_member(path_identifier, member), status: :created)
    audit_success('membership', :create, path_identifier, audit_payload)
  rescue => e
    audit_failure('membership', :create, path_identifier, e.message, audit_payload)
    handle_exception(e)
  end

  def delete
    url_params = permit_url_params(URL_REQUIRED_PARAMS_PATH + [:id])
    log_debug("url_params = #{url_params}")

    auth_del(path_identifier)

    member = Memberships::Member.new(**url_params)
    log_debug("member = #{member}")

    remove_member(path_identifier, member)
    head(:no_content)
    audit_success('membership', :remove, path_identifier)
  rescue => e
    audit_failure('membership', :remove, path_identifier, e.message)
    handle_exception(e)
  end

  private

  def auth_create(identifier)
    auth_action(:update, 'policy', parent_of(identifier), 'branch')
  end

  def auth_del(identifier)
    auth_action(:update, 'policy', parent_of(identifier), 'branch')
  end

  # create
  def add_member(group_identifier, member)
    @membership_service.add_member(current_user, account, group_identifier, member)
  end

  # delete
  def remove_member(group_identifier, member)
    @membership_service.remove_member(current_user, account, group_identifier, member)
  end
end
