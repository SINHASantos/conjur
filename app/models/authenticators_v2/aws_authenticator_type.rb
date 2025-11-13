# frozen_string_literal: true

module AuthenticatorsV2
  class AwsAuthenticatorType < AuthenticatorBaseType
    def format_type
      "aws"
    end
  end
end
