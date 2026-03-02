# frozen_string_literal: true

# K8sObjectLookup is used to lookup Kubernetes object metadata using
# Kubernetes API. This is essentially a facade over the API
#
module Authentication
  module AuthnK8s

    VARIABLE_BEARER_TOKEN ||= 'kubernetes/service-account-token'
    VARIABLE_CA_CERT ||= 'kubernetes/ca-cert'
    VARIABLE_API_URL ||= 'kubernetes/api-url'
    SERVICEACCOUNT_DIR ||= '/var/run/secrets/kubernetes.io/serviceaccount'
    SERVICEACCOUNT_CA_PATH ||= File.join(SERVICEACCOUNT_DIR, 'ca.crt').freeze
    SERVICEACCOUNT_TOKEN_PATH ||= File.join(SERVICEACCOUNT_DIR, 'token').freeze

    # TODO: rename to K8sApiFacade
    class K8sObjectLookup

      class K8sForbiddenError < RuntimeError; end

      attr_reader :cert_store

      def initialize(webservice = nil)
        @webservice = webservice
        @cert_store = OpenSSL::X509::Store.new
        @cert_store.set_default_paths
        Conjur::Certificates::CertUtils.add_chained_cert(@cert_store, ca_cert)

        return unless ENV.key?('SSL_CERT_DIRECTORY')

        Conjur::Certificates::CertUtils.load_certificates(
          @cert_store,
          File.join(ENV['SSL_CERT_DIRECTORY'], 'ca')
        )
      end

      def bearer_token
        @bearer_token ||= K8sContextValue.get(
          @webservice,
          SERVICEACCOUNT_TOKEN_PATH,
          VARIABLE_BEARER_TOKEN
        )&.strip
      end

      def ca_cert
        cert = K8sContextValue.get(
          @webservice,
          SERVICEACCOUNT_CA_PATH,
          VARIABLE_CA_CERT
        )&.strip

        raise Errors::Authentication::AuthnK8s::MissingCertificate if cert.blank?

        cert
      end

      def options
        @options ||= {
          auth_options: {
            bearer_token: bearer_token
          },
          ssl_options: {
            cert_store: @cert_store,
            verify_ssl: OpenSSL::SSL::VERIFY_PEER
          },
          http_proxy_uri: URI.parse(api_url).find_proxy
        }
      end

      def api_url
        # Policy configuration takes precedence over environment variables
        begin
          api_url_from_policy = variable_api_url
          unless api_url_from_policy.blank?
            Rails.logger.debug("Loading Kubernetes API URL from policy configuration (kubernetes/api-url)")
            return api_url_from_policy
          end
        rescue
          # If policy config is not available, fall through to environment variables
          Rails.logger.debug("Policy configuration for kubernetes/api-url not available")
        end

        # Fall back to environment variables if policy config is not present (nil)
        host = ENV['KUBERNETES_SERVICE_HOST']
        port = ENV['KUBERNETES_SERVICE_PORT']

        if host.present? && port.present?
          Rails.logger.debug("Loading Kubernetes API URL from environment variables (KUBERNETES_SERVICE_HOST:KUBERNETES_SERVICE_PORT)")
          "https://#{host}:#{port}"
        else
          Rails.logger.error("Neither policy configuration (kubernetes/api-url) nor environment variables (KUBERNETES_SERVICE_HOST:KUBERNETES_SERVICE_PORT) available for Kubernetes API URL")
          nil
        end
      end

      def variable_api_url
        @variable_api_url ||= @webservice.variable(VARIABLE_API_URL).secret.value
      end

      # Gets the client object to the /api v1 endpoint.
      def kube_client
        KubeClientFactory.client(host_url: api_url, options: options)
      end

      # Locates the Pod with a given IP address.
      #
      # @return nil if no such Pod exists.
      def pod_by_ip(request_ip, namespace)
        # TODO: use "status.podIP" field_selector for versions of k8s that
        # support it the current implementation is a performance optimization
        # for very early K8s versions usage of "status.podIP" field_selector on
        # versions of k8s that do not support it results in no pods returned
        # from #get_pods
        log_api_call(
          method_name: 'get_pods',
          namespace: namespace,
          resource_name: "IP:#{request_ip}"
        ) do
          k8s_client_for_method("get_pods")
            .get_pods(field_selector: "", namespace: namespace)
            .select do |pod|
              # Just in case the filter is mis-implemented on the server side.
              pod.status.podIP == request_ip
            end.first
        end
      end

      # Locates the Pod with a given podname in a namespace.
      #
      # @return nil if no such Pod exists.
      def pod_by_name(podname, namespace)
        log_api_call(
          method_name: 'get_pod',
          namespace: namespace,
          resource_name: podname
        ) do
          k8s_client_for_method("get_pod").get_pod(podname, namespace)
        end
      end

      # Returns the labels hash for a Namespace with a given name.
      #
      # @return nil if no such Namespace exists.
      def namespace_labels_hash(namespace)
        result = log_api_call(
          method_name: 'get_namespace',
          namespace: namespace,
          resource_name: namespace
        ) do
          k8s_client_for_method("get_namespace").get_namespace(namespace)
        end

        result.metadata.labels.to_h unless result.nil?
      end

      # Locates pods matching label selector in a namespace.
      #
      def pods_by_label(label_selector, namespace)
        log_api_call(
          method_name: 'get_pods',
          namespace: namespace,
          resource_name: "label:#{label_selector}"
        ) do
          k8s_client_for_method("get_pods").get_pods(label_selector: label_selector, namespace: namespace)
        end
      end

      # Look up an object according to the resource name. In Kubernetes, the
      # "resource" means something like ReplicaSet, Job, Deployment, etc.
      #
      # Here, resource_name should be the underscore-ized resource, e.g.
      # "replica_set".
      #
      # @return nil if no such object exists.
      def find_object_by_name resource_name, name, namespace
        begin
          log_api_call(
            method_name: "get_#{resource_name}",
            namespace: namespace,
            resource_name: name
          ) do
            handle_object_not_found do
              invoke_k8s_method("get_#{resource_name}", name, namespace)
            end
          end
        rescue KubeException => e
          # This error message can be a bit confusing when multiple authorizers are
          # present, as is the case with GKE (IAM and k8s RBAC).
          # See: https://github.com/kubernetes/kubernetes/issues/52279
          if e.error_code == 403
            raise K8sForbiddenError, e.message
          else
            raise e
          end
        end
      end

      protected

      def invoke_k8s_method method_name, *arguments
        k8s_client_for_method(method_name).send(method_name, *arguments)
      end

      # Methods move around between API versions across releases, so search the
      # client API objects to find the method we are looking for.
      def k8s_client_for_method method_name
        successful_client = nil

        k8s_clients.each do |client, api_version|
          Rails.logger.debug(
            LogMessages::Authentication::AuthnK8s::K8sClientVersionSearchStarting.new(
              method_name,
              api_version
            )
          )

          begin
            if client.respond_to?(method_name)
              successful_client = client

              Rails.logger.debug(
                LogMessages::Authentication::AuthnK8s::K8sClientVersionSearchComplete.new(
                  method_name,
                  api_version
                )
              )

              break
            end
          rescue => e
            raise e if e.is_a?(KubeException) && (e.error_code != 404)

            Rails.logger.debug(
              LogMessages::Authentication::AuthnK8s::K8sClientVersionAttemptFailed.new(
                method_name,
                api_version
              )
            )
          end
        end

        raise Errors::Authentication::AuthnK8s::NoMatchingClient, method_name if successful_client.nil?

        successful_client
      end

      # If more API versions appear, add them here.
      # List them in the order that you want them to be searched for methods.
      # Each entry is a [client, api_version_string] pair so that the version
      # label stays co-located with the client definition and never drifts.
      def k8s_clients
        @clients ||= [
          [kube_client, '/api/v1'],
          [KubeClientFactory.client(
            api: 'apis/apps', version: 'v1', host_url: api_url,
            options: options
          ), '/apis/apps/v1'],
          [KubeClientFactory.client(
            api: 'apis/apps', version: 'v1beta2', host_url: api_url,
            options: options
          ), '/apis/apps/v1beta2'],
          [KubeClientFactory.client(
            api: 'apis/apps', version: 'v1beta1', host_url: api_url,
            options: options
          ), '/apis/apps/v1beta1'],
          [KubeClientFactory.client(
            api: 'apis/extensions', version: 'v1', host_url: api_url,
            options: options
          ), '/apis/extensions/v1'],
          [KubeClientFactory.client(
            api: 'apis/extensions', version: 'v1beta1', host_url: api_url,
            options: options
          ), '/apis/extensions/v1beta1'],
          # OpenShift 3.3 DeploymentConfig
          [KubeClientFactory.client(
            api: 'oapi', version: 'v1', host_url: api_url,
            options: options
          ), '/oapi/v1'],
          # OpenShift 3.7 DeploymentConfig
          [KubeClientFactory.client(
            api: 'apis/apps.openshift.io', version: 'v1', host_url: api_url,
            options: options
          ), '/apis/apps.openshift.io/v1']
        ]
      end

      # returns nil if an HTTP status 404 exception occurs.
      # All other exceptions are re-raised.
      def handle_object_not_found &block
        begin
          yield
        rescue KubeException
          raise unless $!.error_code == 404
        end
      end

      private

      def log_api_call(method_name:, namespace: nil, resource_name: nil)
        # Log start
        Rails.logger.debug(
          LogMessages::Authentication::AuthnK8s::K8sApiCallStarting.new(
            method_name,
            namespace || 'N/A',
            resource_name || 'N/A'
          )
        )

        # Execute the API call
        result = yield if block_given?

        # Log completion
        Rails.logger.debug(
          LogMessages::Authentication::AuthnK8s::K8sApiCallComplete.new(
            method_name
          )
        )

        result
      end
    end
  end
end
