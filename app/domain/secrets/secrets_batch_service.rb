# frozen_string_literal: true

require 'singleton'

module Secrets
  class SecretsBatchService
    include Singleton
    include Domain
    include Logging

    def initialize(
      logger: Rails.logger
    )
      @logger = logger
    end

    def read_batch(role, account, secrets_batch)
      log_debug(role_id: role.id, account:, secrets_batch:)

      { secrets: fetch_secrets(role.id, var_ids(account, secrets_batch.ids))
                   .map { |dsh| make_secret(secrets_batch.use_base64?, dsh) } }
    end

    private

    def var_ids(account, ids)
      ids.map { |id| var_id(account, id) }
    end

    def var_id(account, secret_batch_id)
      "#{account}:variable:#{secret_batch_id}"
    end

    def make_secret(use_base64, db_secret_hash)
      id = db_secret_hash[:id]
      return secret_not_found(id) if for_not_found(db_secret_hash)
      return secret_no_content(id) if db_secret_hash[:no_var]
      return secret_forbidden(id) if db_secret_hash[:cannot_exec]
      secret_ok(use_base64, db_secret_hash)
    end

    def for_not_found(db_secret_hash)
      db_secret_hash[:cannot_read] ||
        db_secret_hash[:not_present] ||
        in_conjur_branch?(db_secret_hash[:id])
    end

    def in_conjur_branch?(id)
      identifier(id).start_with?('conjur/')
    end

    def secret_ok(use_base64, db_secret_hash)
      { id: identifier(db_secret_hash[:id]), status: 200,
        value: secret_value(use_base64, db_secret_hash[:id], db_secret_hash[:value]),
        expires_at: db_secret_hash[:expires_at] }
    end

    def secret_value(use_base64, id, value)
      return '' if value.to_s.empty?
      eav = Slosilo::EncryptedAttributes.decrypt(value, aad: id)
      return Base64.strict_encode64(eav) if use_base64
      eav.force_encoding('UTF-8')
    end

    def secret_no_content(var_id)
      { id: identifier(var_id), status: 204, value: '' }
    end

    def secret_not_found(var_id)
      identifier = identifier(var_id)
      { id: identifier, status: 404,
        description: "Variable #{identifier} not found" }
    end

    def secret_forbidden(var_id)
      { id: identifier(var_id), status: 403,
        description: "Forbidden" }
    end

    def fetch_secrets(role_id, ids)
      sql = <<~SQL
        WITH input_ids AS (
          SELECT id, ord
          FROM UNNEST(?::text[]) WITH ORDINALITY AS t(id, ord)
        )
        SELECT
          i.id AS id,
          (r.resource_id IS NULL) AS not_present,
          (s.resource_id IS NULL) AS no_var,
          NOT is_role_allowed_to(?::text, 'read',    i.id) AS cannot_read,
          NOT is_role_allowed_to(?::text, 'execute', i.id) AS cannot_exec,
          s.value,
          s.expires_at
        FROM input_ids i
        LEFT JOIN resources r ON r.resource_id = i.id
        LEFT JOIN secrets   s ON s.resource_id = i.id
        ORDER BY i.ord;
      SQL

      Sequel::Model.db.fetch(sql, Sequel.pg_array(ids, :text), role_id, role_id).all
    end
  end
end
