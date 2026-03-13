# frozen_string_literal: true

class RoleMembership < Sequel::Model
  unrestrict_primary_key
  
  many_to_one :member,  class: :Role
  many_to_one :role,    class: :Role
  
  def as_json options = {}
    super(options).tap do |response|
      %w[role member policy].each do |field|
        write_id_to_json(response, field)
      end
    end
  end

  # Calculates the longest membership chain passing through this role membership.
  # Uses a recursive SQL function that traverses role_memberships in both directions:
  #   - upward (role_id): finds all groups this role belongs to
  #   - downward (member_id): finds all members nested within this role
  # Returns the sum of the maximum depth found in each direction, representing
  # the total chain length. The search is capped at max_search_depth to prevent
  # infinite loops in case of cycles.
  def longest_membership_chain(max_search_depth)
    db.select(
      Sequel.function(:longest_membership_chain, role_id, max_search_depth)
    ).single_value
  end

  dataset_module do
    def member_of role_ids
      subset_roles = Set.new(role_ids.map{|id| Role[id]}.compact.map(&:role_id))
      where(member_id: subset_roles.to_a)
    end
  end
end
