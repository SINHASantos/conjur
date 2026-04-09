# frozen_string_literal: true

require 'date'

class StatusController < ApplicationController
  include TokenUser
  include ::ActionView::Layouts

  def index
    render('index', layout: false)
  end

  def version
    version = File.read(Rails.root.join('VERSION')).strip

    response.headers['Content-Type'] = 'application/json'
    self.response_body = { version: version }.to_json
  end
end
