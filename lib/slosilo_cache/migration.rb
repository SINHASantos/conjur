# frozen_string_literal: true

require 'sequel'
require 'slosilo'

module SlosiloCache
  module Migration
    # random number for lock
    ADVISORY_LOCK_KEY = 0x534C4F53494C4F

    def with_advisory_lock(&block)
      run("SELECT pg_advisory_lock(#{ADVISORY_LOCK_KEY})")
      begin
        block.call
      ensure
        run("SELECT pg_advisory_unlock(#{ADVISORY_LOCK_KEY})")
      end
    end

    def keystore_table_name
      # Use Slosilo's extension to get the configured keystore table name
      slosilo_keystore
      keystore_table.to_s
    end
  end
end

Sequel.migration do
  up do
    extend Slosilo::Extension
    extend SlosiloCache::Migration

    with_advisory_lock do
      table = keystore_table_name

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
  end

  down do
    extend Slosilo::Extension
    extend SlosiloCache::Migration

    with_advisory_lock do
      table = keystore_table_name

      run <<~SQL
        DROP TRIGGER IF EXISTS slosilo_cache_clear_notify ON #{quote_identifier(table)};
        DROP FUNCTION IF EXISTS slosilo_cache_notify();
      SQL
    end
  end
end
