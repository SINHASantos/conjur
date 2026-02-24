module Authentication
  module AuthnK8s
    # K8sContextValue attempts to retrieve a value from a file, falling back to
    # a value stored in a Conjur variable.

    # In the context of retrieving service account tokens, this arrangement
    # allows Conjur instances running inside a K8s cluster to use different
    # service account tokens (defined on their file system) while any instances
    # running outside the cluster are forced to use the same service account
    # token (defined in policy).

    # If we were to flip the priorities such that policy was preferred, it would
    # force all Conjur instances running both outside and inside a K8s cluster
    # to use the service account token defined in policy, which likely would not
    # be the desired behavior.
    class K8sContextValue
      def self.get webservice, file_name, variable_id
        # Policy/variable configuration takes precedence over mounted files
        if webservice.present?
          begin
            variable_value = webservice.variable(variable_id).secret.value
            unless variable_value.blank?
              Rails.logger.debug("Loading #{variable_id} from policy configuration")
              return variable_value
            end
          rescue
            # If policy config is not available, fall through to file
            Rails.logger.debug("Policy configuration for #{variable_id} not available")
          end
        end

        # Fall back to mounted file if policy config is not present (nil)
        if File.exist?(file_name)
          Rails.logger.debug("Loading #{variable_id} from mounted file at #{file_name}")
          return File.read(file_name)
        end

        Rails.logger.debug("Neither policy configuration nor mounted file available for #{variable_id}")
        nil
      rescue
        Rails.logger.debug("Error retrieving #{variable_id}, returning nil")
        nil
      end
    end
  end
end
