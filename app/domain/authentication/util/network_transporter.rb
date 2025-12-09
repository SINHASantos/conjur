# frozen_string_literal: true

module Authentication
  module Util
    class NetworkTransporter
      def initialize(
        hostname:,
        ca_certificate: nil,
        proxy: nil,
        http: Net::HTTP,
        certificate_utilities: Conjur::Certificates::CertUtils,
        http_post: Net::HTTP::Post
      )
        # Set the default hostname
        @uri = URI(hostname)
        # Stripping path if present
        @uri.path = ''

        @ca_certificate = ca_certificate

        @http = http
        @http_post = http_post # to facilitate dependency injection for testing
        @certificate_utilities = certificate_utilities

        # Find and set the proxy
        @proxy = identify_proxy(proxy)

        @success = Responses::Success
        @failure = Responses::Failure
      end

      def get(path)
        as_response do
          get_request(request_path: path)
        end
      end

      # Possible request types are :form and :json. Default is :form.
      #   - If request_type is :json, the body is expected to be a hash. It is
      #     converted to JSON and the Content-Type header is set
      #     to 'application/json'
      #   - If request_type is :form, the body expected to be a hash. It is
      #     converted to form data and the Content-Type header is set
      #     to 'application/x-www-form-urlencoded'.
      # Possible error response types are :none, :json and :oidc. Default is :none.
      #   - If error_type is :json, the body is expected to be a hash. It is
      #     converted to JSON and returned to the client consumer.
      #   - If error_type is :oidc, the body is expected to contain keys
      #     error and error_description. It is returned to the logs in
      #     human-readable form.
      #   - If error_type is :none, the body is expected to be empty or
      #     negligible. The client consumer receives a canned, templated message.
      def post(path:, body: '', basic_auth: [], headers: {}, request_type: :form, error_type: :none)
        as_response(error_type: error_type) do
          post_request(path: path, body: body, basic_auth: basic_auth, headers: headers, request_type: request_type)
        end
      end

      private

      def identify_proxy(proxy)
        proxy_url = if proxy.present?
          proxy
        elsif @uri.scheme == 'https'
          ENV['HTTPS_PROXY'] || ENV['https_proxy'] || ENV['ALL_PROXY']
        else
          ENV['http_proxy'] || ENV['ALL_PROXY']
        end

        proxy_uri = URI.parse(proxy_url.to_s)
        proxy_uri.is_a?(URI::HTTP) ? proxy_uri : nil
      end

      def get_request(request_path:)
        http_client.start do |http|
          http.get(URI(request_path).path)
        end
      end

      # Body parameter accepts a hash or a string. Hashes are converted to form data.
      def post_request(path:, body: '', request_type: :form, basic_auth: [], headers: {})
        http_client.start do |http|
          request = @http_post.new(URI(path).path)
          headers.each do |key, value|
            request[key] = value
          end
          if body.is_a?(Hash) && request_type == :form
            request.set_form_data(body)
          elsif body.is_a?(Hash) && request_type == :json
            request.body = body.to_json
            request['Content-Type'] = 'application/json'
          else
            request.body = body
          end
          request.basic_auth(*basic_auth) unless basic_auth.empty?
          http.request(request)
        end
      end

      def as_response(error_type: :none, &block)
        response = block.call
        if response.code.to_i >= 200 && response.code.to_i < 300
          return @success.new(JSON.parse(response.body.to_s))
        end

        case error_type
        when :oidc
          error_body = JSON.parse(response.body.to_s)
          oidc_error = "OIDC Error: #{error_body['error'] || 'invalid_request'} - #{error_body['error_description'] ||
            "Error Response Code: '#{response.code}' from '#{response.uri}'"}"
          return @failure.new(oidc_error, status: response.code.to_i)
        when :json
          return @failure.new(JSON.parse(response.body.to_s))
        else
          @failure.new("Error Response Code: '#{response.code}' from '#{response.uri}'")
        end
      rescue JSON::ParserError => e
        @failure.new("Invalid JSON: #{e.message}", exception: e, status: :bad_request)
      rescue => e
        @failure.new("Invalid Request: #{e.message}", exception: e, status: :bad_request)
      end

      # If proxy settings are set via environment variables, grab the relevant settingsq
      def proxy_settings
        return [] unless @proxy.present?

        # if proxy is present, set with the appropriate host and port. Set username and password if present.
        [@proxy.hostname, @proxy.port, @proxy.user, @proxy.password].compact
      end

      def http_client
        @http_client ||= begin
          http = @http.new(@uri.hostname, @uri.port, *proxy_settings)
          return http unless @uri.instance_of?(URI::HTTPS)

          # Enable SSL support
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER

          store = OpenSSL::X509::Store.new
          # If CA Certificate is available, add it to the certificate store
          if @ca_certificate.present?
            @certificate_utilities.add_chained_cert(store, @ca_certificate)
          else
            # Auto-include system CAs unless a CA has been defined
            store.set_default_paths
          end
          http.cert_store = store

          # return the http object
          http
        end
      end
    end
  end
end
