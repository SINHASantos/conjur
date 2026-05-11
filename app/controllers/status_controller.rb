# frozen_string_literal: true

require 'date'

class StatusController < ApplicationController
  include TokenUser
  include ::ActionView::Layouts

  validate_query_params []
  validate_query_params_for_action :index, %i[format]

  def index
    render('index', layout: false)
  end

  def version
    version = File.read(Rails.root.join('VERSION')).strip

    response.headers['Content-Type'] = 'application/json'
    self.response_body = { version: version }.to_json
  end
end
