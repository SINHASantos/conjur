# frozen_string_literal: true

Sequel.migration do
  table = :slosilo_keystore

  up do
    run <<~SQL
        CREATE OR REPLACE FUNCTION slosilo_cache_notify()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
        PERFORM pg_notify('clear_slosilo_cache', '');
        RETURN NULL;
      END;
        $$;
    SQL

    run <<~SQL
      DROP TRIGGER IF EXISTS slosilo_cache_clear_notify ON #{quote_identifier(table)};
      CREATE TRIGGER slosilo_cache_clear_notify
      AFTER UPDATE OR DELETE ON #{quote_identifier(table)}
      FOR EACH STATEMENT
      EXECUTE FUNCTION slosilo_cache_notify();
    SQL
  end

  down do
    run <<~SQL
      DROP TRIGGER IF EXISTS slosilo_cache_clear_notify ON #{quote_identifier(table)};
      DROP FUNCTION IF EXISTS slosilo_cache_notify();
    SQL
  end
end
