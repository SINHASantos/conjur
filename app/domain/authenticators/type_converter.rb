module Authenticators
  # Convert type to branch and vice-versa for V2 Authenticators usage
  module TypeConverter

    # Map between authenticator type and branch
    # @param [String] - the type to convert
    # @return [String] - the appropriate branch name
    # @note - including the account
    def self.get_full_branch_from_type(type)
      branch_name = Authenticators::TypeConverter.get_branch_from_type(type)
      "conjur/#{branch_name}"
    end

    # Map between authenticator type and branch
    # @param [String] - the type to convert
    # @return [String] - the appropriate branch name
    # @note - excluding the account
    def self.get_branch_from_type(type)
      {
        # "aws_iam" => "authn-iam",
        "aws" => "authn-iam",
        # "certificate" => "authn-cert",
        "cert" => "authn-cert",
        "api_key" => "authn/api-key"
      }.fetch(type, "authn-#{type}")
    end

    # Map between authenticator branch and type
    # @param [String] - the branch name to convert
    # @return [String] - the appropriate type
    def self.get_type_from_branch(authn_branch)
      {
        # "authn-iam" => "aws_iam",
        "authn-iam" => "aws",
        # "authn-cert" => "certificate",
        "authn-cert" => "cert",
        "authn/api-key" => "api_key"
      }.fetch(authn_branch, authn_branch.split("-").last)
    end
  end
end
