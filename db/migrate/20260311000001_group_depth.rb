# frozen_string_literal: true

Sequel.migration do
  up do
    execute <<~SQL
      CREATE OR REPLACE FUNCTION longest_membership_chain(p_role_id TEXT, max_search_depth INT) RETURNS INTEGER
      LANGUAGE sql STABLE
      AS $$
        WITH RECURSIVE up(id, depth) AS (
          SELECT p_role_id, 0
          UNION ALL
          SELECT rm.role_id, up.depth + 1
          FROM role_memberships rm
          JOIN up ON rm.member_id = up.id
          WHERE COALESCE(rm.ownership, false) = false
            AND up.depth <= max_search_depth
        ),
        down(id, depth) AS (
          SELECT p_role_id, 0
          UNION ALL
          SELECT rm.member_id, down.depth + 1
          FROM role_memberships rm
          JOIN down ON rm.role_id = down.id
          WHERE COALESCE(rm.ownership, false) = false
            AND down.depth <= max_search_depth
        ),
        maxes AS (
          SELECT
            COALESCE((SELECT MAX(depth) FROM up),   0) AS up_max,
            COALESCE((SELECT MAX(depth) FROM down), 0) AS down_max
        )
        SELECT up_max + down_max FROM maxes;
      $$;
    SQL
  end

  down do
    execute "DROP FUNCTION IF EXISTS longest_membership_chain(TEXT, INT)"
  end
end

