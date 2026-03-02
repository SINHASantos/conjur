# frozen_string_literal: true

require 'openssl'
require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::K8sObjectLookup) do
  let(:webservice) do
    Authentication::Webservice.new(
      account: 'MockAccount',
      authenticator_name: 'authn-k8s',
      service_id: 'MockService'
    )
  end

  let(:proxy_uri) { URI.parse("http://uri") }

  let(:cert_raw) do
    "-----BEGIN CERTIFICATE-----
MIIDhzCCAm+gAwIBAgIJAJnsrJ1+j9MhMA0GCSqGSIb3DQEBCwUAMD0xETAPBgNV
BAoTCGN1Y3VtYmVyMRIwEAYDVQQLEwlDb25qdXIgQ0ExFDASBgNVBAMTC2N1a2Ut
bWFzdGVyMB4XDTE1MTAwNzE2MzAwM1oXDTI1MTAwNDE2MzAwM1owPTERMA8GA1UE
ChMIY3VjdW1iZXIxEjAQBgNVBAsTCUNvbmp1ciBDQTEUMBIGA1UEAxMLY3VrZS1t
YXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsuZ06Ld4JDhxZ
FcxKVxu7MTjXVv6W8pI7qFKmgr39aNqmDpKYJ1H9aM+r9zaTAeithpM4wJpVswkJ
d0RSuKdm1LOx11yHLyZ1OvlPHFhsVWdZIQZ6R9srhPYBUCMem4sHR5IAcBBX+HkR
35gaPYUl1uFV/9zCniekt92Kdta+it1WL7XinXTBURlhDawiD/kv1C9x6dICEJVe
IT/jRohmqHAoM/JSOQTthaDli3Qvu5K8XAx8UXvWVmv3eStZFVDbC4ZEueRd9KAe
4IZ5FxdpFYkPBgt2lBYeydYKRShyYrDKye1uJBDkeplNaYW4cS4mOhYuRkdKn7MH
uY/xb1lFAgMBAAGjgYkwgYYwKQYDVR0RBCIwIIILY3VrZS1tYXN0ZXKCCWxvY2Fs
aG9zdIIGY29uanVyMB0GA1UdDgQWBBRHpGF7aQbHdORYgQKDC2hV6NzEKzAfBgNV
HSMEGDAWgBRHpGF7aQbHdORYgQKDC2hV6NzEKzAMBgNVHRMEBTADAQH/MAsGA1Ud
DwQEAwIB5jANBgkqhkiG9w0BAQsFAAOCAQEAGZT9Wek1hYluIVaxu03wSKCKIJ4p
KxTHw+mLDapg1y9t3Fa/5IQQK0Bx0xGU2qWiQKjda3vdFPJWO6l6XJvsUY5Nwtm5
Gcsk8l3L/zWCrjrFTH3TdVad5E+DTwVhThelmEjw68AyM+WuOL61j0MItd9mLW74
Lv2zouj9nQBdnUBHWQ0EL/9d5cfaCVu/bFlDfYt7Yj0IzXCuaWZfJeHodU1hmqVX
BvYRjnTB2LSxfmSnkrCeFPmhE11bWVtsLIdrGIgtEMX0/s9xg58QuNnva1U3pJsW
RjvSxre4Xg2qlI9Laybb4oZ4g6DI8hRbL0VdFAsveg6SXg2RxgJcXeJUFw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIVAKW1gdmOFrXt6xB0iQmYQ4z8Pf+kMA0GCSqGSIb3DQEB
CwUAMD0xETAPBgNVBAoTCGN1Y3VtYmVyMRIwEAYDVQQLEwlDb25qdXIgQ0ExFDAS
BgNVBAMTC2N1a2UtbWFzdGVyMB4XDTE1MTAwNzE2MzAwNloXDTI1MTAwNDE2MzAw
NlowFjEUMBIGA1UEAwwLY3VrZS1tYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC9e8bGIHOLOypKA4lsLcAOcDLAq+ICuVxn9Vg0No0m32Ok/K7G
uEGtlC8RidObntblUwqdX2uP7mqAQm19j78UTl1KT97vMmmFrpVZ7oQvEm1FUq3t
FBmJglthJrSbpdZjLf7a7eL1NnunkfBdI1DK9QL9ndMjNwZNFbXhld4fC5zuSr/L
PxawSzTEsoTaB0Nw0DdRowaZgrPxc0hQsrj9OF20gTIJIYO7ctZzE/JJchmBzgI4
CdfAYg7zNS+0oc0ylV0CWMerQtLICI6BtiQ482bCuGYJ00NlDcdjd3w+A2cj7PrH
wH5UhtORL5Q6i9EfGGUCDbmfpiVD9Bd3ukbXAgMBAAGjXDBaMA4GA1UdDwEB/wQE
AwIFoDAdBgNVHQ4EFgQU2jmj7l5rSw0yVb/vlWAYkK/YBwkwKQYDVR0RBCIwIIIL
Y3VrZS1tYXN0ZXKCCWxvY2FsaG9zdIIGY29uanVyMA0GCSqGSIb3DQEBCwUAA4IB
AQBCepy6If67+sjuVnT9NGBmjnVaLa11kgGNEB1BZQnvCy0IN7gpLpshoZevxYDR
3DnPAetQiZ70CSmCwjL4x6AVxQy59rRj0Awl9E1dgFTYI3JxxgLsI9ePdIRVEPnH
dhXqPY5ZIZhvdHlLStjsXX7laaclEtMeWfSzxe4AmP/Sm/er4ks0gvLQU6/XJNIu
RnRH59ZB1mZMsIv9Ii790nnioYFR54JmQu1JsIib77ZdSXIJmxAtraJSTLcZbU1E
+SM3XCE423Xols7onyluMYDy3MCUTFwoVMRBcRWCAk5gcv6XvZDfLi6Zwdne6x3Y
bGenr4vsPuSFsycM03/EcQDT
-----END CERTIFICATE-----\n\n
"
  end

  let(:cert_raw_stripped) do
    "-----BEGIN CERTIFICATE-----
MIIDhzCCAm+gAwIBAgIJAJnsrJ1+j9MhMA0GCSqGSIb3DQEBCwUAMD0xETAPBgNV
BAoTCGN1Y3VtYmVyMRIwEAYDVQQLEwlDb25qdXIgQ0ExFDASBgNVBAMTC2N1a2Ut
bWFzdGVyMB4XDTE1MTAwNzE2MzAwM1oXDTI1MTAwNDE2MzAwM1owPTERMA8GA1UE
ChMIY3VjdW1iZXIxEjAQBgNVBAsTCUNvbmp1ciBDQTEUMBIGA1UEAxMLY3VrZS1t
YXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsuZ06Ld4JDhxZ
FcxKVxu7MTjXVv6W8pI7qFKmgr39aNqmDpKYJ1H9aM+r9zaTAeithpM4wJpVswkJ
d0RSuKdm1LOx11yHLyZ1OvlPHFhsVWdZIQZ6R9srhPYBUCMem4sHR5IAcBBX+HkR
35gaPYUl1uFV/9zCniekt92Kdta+it1WL7XinXTBURlhDawiD/kv1C9x6dICEJVe
IT/jRohmqHAoM/JSOQTthaDli3Qvu5K8XAx8UXvWVmv3eStZFVDbC4ZEueRd9KAe
4IZ5FxdpFYkPBgt2lBYeydYKRShyYrDKye1uJBDkeplNaYW4cS4mOhYuRkdKn7MH
uY/xb1lFAgMBAAGjgYkwgYYwKQYDVR0RBCIwIIILY3VrZS1tYXN0ZXKCCWxvY2Fs
aG9zdIIGY29uanVyMB0GA1UdDgQWBBRHpGF7aQbHdORYgQKDC2hV6NzEKzAfBgNV
HSMEGDAWgBRHpGF7aQbHdORYgQKDC2hV6NzEKzAMBgNVHRMEBTADAQH/MAsGA1Ud
DwQEAwIB5jANBgkqhkiG9w0BAQsFAAOCAQEAGZT9Wek1hYluIVaxu03wSKCKIJ4p
KxTHw+mLDapg1y9t3Fa/5IQQK0Bx0xGU2qWiQKjda3vdFPJWO6l6XJvsUY5Nwtm5
Gcsk8l3L/zWCrjrFTH3TdVad5E+DTwVhThelmEjw68AyM+WuOL61j0MItd9mLW74
Lv2zouj9nQBdnUBHWQ0EL/9d5cfaCVu/bFlDfYt7Yj0IzXCuaWZfJeHodU1hmqVX
BvYRjnTB2LSxfmSnkrCeFPmhE11bWVtsLIdrGIgtEMX0/s9xg58QuNnva1U3pJsW
RjvSxre4Xg2qlI9Laybb4oZ4g6DI8hRbL0VdFAsveg6SXg2RxgJcXeJUFw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIVAKW1gdmOFrXt6xB0iQmYQ4z8Pf+kMA0GCSqGSIb3DQEB
CwUAMD0xETAPBgNVBAoTCGN1Y3VtYmVyMRIwEAYDVQQLEwlDb25qdXIgQ0ExFDAS
BgNVBAMTC2N1a2UtbWFzdGVyMB4XDTE1MTAwNzE2MzAwNloXDTI1MTAwNDE2MzAw
NlowFjEUMBIGA1UEAwwLY3VrZS1tYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC9e8bGIHOLOypKA4lsLcAOcDLAq+ICuVxn9Vg0No0m32Ok/K7G
uEGtlC8RidObntblUwqdX2uP7mqAQm19j78UTl1KT97vMmmFrpVZ7oQvEm1FUq3t
FBmJglthJrSbpdZjLf7a7eL1NnunkfBdI1DK9QL9ndMjNwZNFbXhld4fC5zuSr/L
PxawSzTEsoTaB0Nw0DdRowaZgrPxc0hQsrj9OF20gTIJIYO7ctZzE/JJchmBzgI4
CdfAYg7zNS+0oc0ylV0CWMerQtLICI6BtiQ482bCuGYJ00NlDcdjd3w+A2cj7PrH
wH5UhtORL5Q6i9EfGGUCDbmfpiVD9Bd3ukbXAgMBAAGjXDBaMA4GA1UdDwEB/wQE
AwIFoDAdBgNVHQ4EFgQU2jmj7l5rSw0yVb/vlWAYkK/YBwkwKQYDVR0RBCIwIIIL
Y3VrZS1tYXN0ZXKCCWxvY2FsaG9zdIIGY29uanVyMA0GCSqGSIb3DQEBCwUAA4IB
AQBCepy6If67+sjuVnT9NGBmjnVaLa11kgGNEB1BZQnvCy0IN7gpLpshoZevxYDR
3DnPAetQiZ70CSmCwjL4x6AVxQy59rRj0Awl9E1dgFTYI3JxxgLsI9ePdIRVEPnH
dhXqPY5ZIZhvdHlLStjsXX7laaclEtMeWfSzxe4AmP/Sm/er4ks0gvLQU6/XJNIu
RnRH59ZB1mZMsIv9Ii790nnioYFR54JmQu1JsIib77ZdSXIJmxAtraJSTLcZbU1E
+SM3XCE423Xols7onyluMYDy3MCUTFwoVMRBcRWCAk5gcv6XvZDfLi6Zwdne6x3Y
bGenr4vsPuSFsycM03/EcQDT
-----END CERTIFICATE-----"
  end

  context "inside of kubernetes" do
    include_context "running in kubernetes"

    before do
      allow(URI).to receive_message_chain(:parse, :find_proxy)
        .and_return(proxy_uri)
    end

    context "instantiation" do
      it "does not require a webservice" do
        expect { Authentication::AuthnK8s::K8sObjectLookup.new }.not_to raise_error
      end
    end

    subject { Authentication::AuthnK8s::K8sObjectLookup.new(webservice) }

    it "gets the correct api url" do
      expect(subject.api_url).to eq("https://#{kubernetes_api_url}:#{kubernetes_api_port}")
    end

    it "has the correct ssl options" do
      expect(subject.options[:ssl_options]).to include(:cert_store, verify_ssl: OpenSSL::SSL::VERIFY_PEER)
    end

    it "has the correct auth options" do
      expect(subject.options[:auth_options]).to include(bearer_token: kubernetes_service_token)
    end

    it "has the correct proxy uri" do
      expect(subject.options[:http_proxy_uri]).to equal(proxy_uri)
    end
  end

  context "outside of kubernetes" do
    include_context "running outside kubernetes"

    context "instantiation" do
      it "requires a webservice" do
        allow(Authentication::AuthnK8s::K8sContextValue).to receive(:get)
          .with(nil,
                Authentication::AuthnK8s::SERVICEACCOUNT_CA_PATH,
                Authentication::AuthnK8s::VARIABLE_CA_CERT)
          .and_return(nil)

        expect { Authentication::AuthnK8s::K8sObjectLookup.new }.to raise_error(Errors::Authentication::AuthnK8s::MissingCertificate)
      end
    end

    subject { Authentication::AuthnK8s::K8sObjectLookup.new(webservice) }

    it "gets the correct api url" do
      expect(subject.api_url).to eq(kubernetes_api_url)
    end

    it "has the correct ssl options" do
      expect(subject.options[:ssl_options]).to include(:cert_store, verify_ssl: OpenSSL::SSL::VERIFY_PEER)
    end

    it "has the correct auth options" do
      expect(subject.options[:auth_options]).to include(bearer_token: kubernetes_service_token)
    end

    context "when context value contains whitespaces" do
      it "returns the ca_cert value without whitespace" do
        allow(Authentication::AuthnK8s::K8sContextValue).to receive(:get)
          .with(webservice,
                Authentication::AuthnK8s::SERVICEACCOUNT_CA_PATH,
                Authentication::AuthnK8s::VARIABLE_CA_CERT)
          .and_return(cert_raw)

        expect(subject.ca_cert).to eq(cert_raw_stripped)
      end

      it "returns the bearer_token value without whitespace" do
        allow(Authentication::AuthnK8s::K8sContextValue).to receive(:get)
          .with(webservice,
                Authentication::AuthnK8s::SERVICEACCOUNT_TOKEN_PATH,
                Authentication::AuthnK8s::VARIABLE_BEARER_TOKEN)
          .and_return("MockToken\n")

        expect(subject.bearer_token).to eq("MockToken")
      end
    end

    context "Logging Behavior" do
      let(:subject) { Authentication::AuthnK8s::K8sObjectLookup.new(webservice) }

      it "logs API calls" do
        allow(Rails.logger).to receive(:debug)
        mock_pod = double(status: double(podIP: '192.168.1.1'))
        mock_client = double
        allow(mock_client).to receive(:get_pods).and_return([mock_pod])
        allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)

        expect(Rails.logger).to receive(:debug).at_least(:once)
        subject.pod_by_ip('192.168.1.1', 'default')
      end
    end

    context "Public API Methods" do
      let(:subject) { Authentication::AuthnK8s::K8sObjectLookup.new(webservice) }

      describe "#pod_by_ip" do
        it "returns pod when found" do
          mock_pod = double(status: double(podIP: '192.168.1.1'))
          mock_client = double
          allow(mock_client).to receive(:get_pods).and_return([mock_pod])
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          result = subject.pod_by_ip('192.168.1.1', 'default')

          expect(result).to eq(mock_pod)
        end

        it "returns nil when pod not found" do
          mock_client = double
          allow(mock_client).to receive(:get_pods).and_return([])
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          result = subject.pod_by_ip('192.168.1.99', 'default')

          expect(result).to be_nil
        end

        it "filters pods by IP address correctly" do
          pod1 = double(status: double(podIP: '192.168.1.1'))
          pod2 = double(status: double(podIP: '192.168.1.2'))
          mock_client = double
          allow(mock_client).to receive(:get_pods).and_return([pod1, pod2])
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          result = subject.pod_by_ip('192.168.1.2', 'default')

          expect(result).to eq(pod2)
        end
      end

      describe "#pod_by_name" do
        it "returns pod when found" do
          mock_pod = double
          mock_client = double
          allow(mock_client).to receive(:get_pod).with('my-pod', 'default').and_return(mock_pod)
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          result = subject.pod_by_name('my-pod', 'default')

          expect(result).to eq(mock_pod)
        end

        it "raises KubeException when pod not found" do
          mock_client = double
          allow(mock_client).to receive(:get_pod).and_raise(KubeException.new(404, 'not found', nil))
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          expect do
            subject.pod_by_name('nonexistent', 'default')
          end.to raise_error(KubeException)
        end
      end

      describe "#namespace_labels_hash" do
        it "returns labels hash when namespace found" do
          mock_labels = { 'env' => 'prod', 'team' => 'platform' }
          mock_namespace = double(metadata: double(labels: mock_labels))
          mock_client = double
          allow(mock_client).to receive(:get_namespace).and_return(mock_namespace)
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          result = subject.namespace_labels_hash('default')

          expect(result).to eq(mock_labels)
        end

        it "returns nil when namespace not found" do
          mock_client = double
          allow(mock_client).to receive(:get_namespace).and_return(nil)
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          result = subject.namespace_labels_hash('nonexistent')

          expect(result).to be_nil
        end

        it "handles namespace with nil labels" do
          mock_namespace = double(metadata: double(labels: nil))
          mock_client = double
          allow(mock_client).to receive(:get_namespace).and_return(mock_namespace)
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          result = subject.namespace_labels_hash('default')

          expect(result).to eq({})
        end
      end

      describe "#pods_by_label" do
        it "returns pods matching label selector" do
          mock_pod1 = double
          mock_pod2 = double
          mock_client = double
          allow(mock_client).to receive(:get_pods)
            .with(label_selector: 'app=web', namespace: 'default')
            .and_return([mock_pod1, mock_pod2])
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          result = subject.pods_by_label('app=web', 'default')

          expect(result).to eq([mock_pod1, mock_pod2])
        end

        it "returns empty array when no pods match" do
          mock_client = double
          allow(mock_client).to receive(:get_pods).and_return([])
          allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(mock_client)
          allow(Rails.logger).to receive(:debug)

          result = subject.pods_by_label('app=nonexistent', 'default')

          expect(result).to eq([])
        end
      end

      describe "#find_object_by_name" do
        it "delegates to invoke_k8s_method" do
          # This test just verifies the method exists and can be called
          # Further testing happens through find_object_by_name behavior tests
          allow(subject).to receive(:invoke_k8s_method).and_raise(KubeException.new(404, 'not found', nil))
          allow(Rails.logger).to receive(:debug)

          result = subject.find_object_by_name('job', 'missing-job', 'default')

          expect(result).to be_nil
        end
      end
    end

    context "Error Handling" do
      let(:subject) { Authentication::AuthnK8s::K8sObjectLookup.new(webservice) }

      it "returns nil for 404 errors (not found)" do
        allow(subject).to receive(:invoke_k8s_method).and_raise(KubeException.new(404, 'not found', nil))
        allow(Rails.logger).to receive(:debug)

        result = subject.find_object_by_name('job', 'missing', 'default')

        expect(result).to be_nil
      end

      it "raises K8sForbiddenError for 403 errors" do
        allow(subject).to receive(:invoke_k8s_method).and_raise(KubeException.new(403, 'forbidden', nil))
        allow(Rails.logger).to receive(:debug)

        expect do
          subject.find_object_by_name('statefulset', 'sts', 'default')
        end.to raise_error(Authentication::AuthnK8s::K8sObjectLookup::K8sForbiddenError)
      end

      it "re-raises other KubeExceptions" do
        allow(subject).to receive(:invoke_k8s_method).and_raise(KubeException.new(500, 'error', nil))
        allow(Rails.logger).to receive(:debug)

        expect do
          subject.find_object_by_name('pod', 'pod', 'default')
        end.to raise_error(KubeException)
      end
    end

    context "k8s_client_for_method branch coverage" do
      let(:subject) { Authentication::AuthnK8s::K8sObjectLookup.new(webservice) }

      it "finds client with matching method on first attempt" do
        matching_client = double
        allow(matching_client).to receive(:respond_to?).with('get_pods').and_return(true)
        allow(matching_client).to receive(:get_pods).and_return([])
        allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(matching_client)
        allow(Rails.logger).to receive(:debug)

        result = subject.pod_by_ip('192.168.1.1', 'default')

        expect(result).to be_nil
      end

      it "skips clients without the method and continues searching" do
        non_matching_client = double
        matching_client = double
        expected_result = double
        allow(non_matching_client).to receive(:respond_to?).with('get_stateful_set').and_return(false)
        allow(matching_client).to receive(:respond_to?).with('get_stateful_set').and_return(true)
        allow(matching_client).to receive(:get_stateful_set).and_return(expected_result)

        allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client)
          .and_return(non_matching_client, matching_client)
        allow(Rails.logger).to receive(:debug)

        result = subject.find_object_by_name('stateful_set', 'statefulset', 'default')

        expect(result).to eq(expected_result)
      end

      it "continues searching on 404 KubeException from respond_to?" do
        client_with_404 = double
        matching_client = double
        expected_result = double
        allow(client_with_404).to receive(:respond_to?).and_raise(KubeException.new(404, 'not found', nil))
        allow(matching_client).to receive(:respond_to?).with('get_deployment').and_return(true)
        allow(matching_client).to receive(:get_deployment).and_return(expected_result)

        allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client)
          .and_return(client_with_404, matching_client)
        allow(Rails.logger).to receive(:debug)

        result = subject.find_object_by_name('deployment', 'deployment', 'default')

        expect(result).to eq(expected_result)
      end

      it "re-raises non-404 KubeException from respond_to?" do
        client_with_error = double
        allow(client_with_error).to receive(:respond_to?).and_raise(KubeException.new(403, 'forbidden', nil))
        allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client).and_return(client_with_error)
        allow(Rails.logger).to receive(:debug)

        expect do
          subject.pod_by_name('pod', 'default')
        end.to raise_error(KubeException) { |e| expect(e.error_code).to eq(403) }
      end

      it "continues searching on non-KubeException from respond_to?" do
        client_with_runtime_error = double
        matching_client = double
        expected_result = double
        allow(client_with_runtime_error).to receive(:respond_to?).and_raise(StandardError, 'unexpected error')
        allow(matching_client).to receive(:respond_to?).with('get_job').and_return(true)
        allow(matching_client).to receive(:get_job).and_return(expected_result)

        allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client)
          .and_return(client_with_runtime_error, matching_client)
        allow(Rails.logger).to receive(:debug)

        result = subject.find_object_by_name('job', 'job', 'default')

        expect(result).to eq(expected_result)
      end

      it "raises NoMatchingClient when no clients have the method" do
        client1 = double
        client2 = double
        allow(client1).to receive(:respond_to?).and_return(false)
        allow(client2).to receive(:respond_to?).and_return(false)

        allow(Authentication::AuthnK8s::KubeClientFactory).to receive(:client)
          .and_return(client1, client2)
        allow(Rails.logger).to receive(:debug)

        expect do
          subject.find_object_by_name('nonexistent_method', 'missing', 'default')
        end.to raise_error(Errors::Authentication::AuthnK8s::NoMatchingClient)
      end
    end

    context "Client Configuration" do
      let(:subject) { Authentication::AuthnK8s::K8sObjectLookup.new(webservice) }

      it "caches options after first call" do
        first_call = subject.options
        second_call = subject.options

        expect(first_call).to equal(second_call)
      end

      it "caches bearer token after first call" do
        first_token = subject.bearer_token
        second_token = subject.bearer_token

        expect(first_token).to eq(second_token)
      end
    end

    context "when both policy config and environment variables exist" do
      let(:policy_api_url) { "https://policy.k8s.local:6443" }
      let(:env_api_host) { "env.k8s.local" }
      let(:env_api_port) { "5443" }

      before do
        # Set policy API URL via webservice variable
        allow(webservice).to receive(:variable)
          .with(Authentication::AuthnK8s::VARIABLE_API_URL)
          .and_return(double("MockVariable", secret: double("MockSecret", value: policy_api_url)))

        # Set environment variables
        allow(ENV).to receive(:[]).and_call_original
        allow(ENV).to receive(:[])
          .with("KUBERNETES_SERVICE_HOST")
          .and_return(env_api_host)

        allow(ENV).to receive(:[])
          .with("KUBERNETES_SERVICE_PORT")
          .and_return(env_api_port)
      end

      it "uses the policy API URL instead of environment variables" do
        # Policy config should take precedence: return policy_api_url, not env variables
        expect(subject.api_url).to eq(policy_api_url)
      end
    end
  end
end
