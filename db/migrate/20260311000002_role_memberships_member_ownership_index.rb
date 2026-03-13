# frozen_string_literal: true

# This index supports the recursive CTE in the longest_membership_chain SQL function.
# The function traverses role_memberships in two directions:
#   - upward: joining on member_id to find all groups a role belongs to
#   - downward: joining on role_id to find all nested members within a role
# Both traversal directions filter out ownership records (ownership = false).
# By indexing (member_id, ownership) together, PostgreSQL can efficiently locate
# non-ownership rows by member_id in a single index scan during each recursive
# step, avoiding full table scans on every level of the chain traversal.

Sequel.migration do
  up do
    execute <<~SQL
      CREATE INDEX IF NOT EXISTS idx_role_memberships_member_ownership
        ON role_memberships (member_id, ownership);
    SQL
  end

  down do
    execute "DROP INDEX IF EXISTS idx_role_memberships_member_ownership"
  end
end
