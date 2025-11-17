# frozen_string_literal: true

class ProvidersController < ApplicationController
  def index
    contract = Authentication::AuthnOidc::V2::Validations::AuthenticatorConfiguration
    validator = DB::Validation.new(contract)

    authenticators = DB::Repository::AuthenticatorRepository.new.find_all(
      account: params[:account],
      type: params[:authenticator]
    ).bind do |response|
      response.map do |authenticator|
        # perform validation on each record
        result = validator.validate(authenticator.provider_details)

        unless result.success?
          logger.info(
            LogMessages::Authentication::AuthnOidc::InstanceMisconfigured.new(
              authenticator.service_id,
              result.to_s
            )
          )
          next
        end

        authenticator
      end.compact
    end

    render(
      json: Authentication::AuthnOidc::V2::Views::ProviderContext.new.call(
        authenticators: authenticators
      )
    )
  end
end
