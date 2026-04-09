# frozen_string_literal: true

require 'spec_helper'

describe 'version endpoint', type: :request do
  it 'returns the conjur version' do
    expected_version = File.read(Rails.root.join('VERSION')).strip

    get '/version'

    expect(response).to have_http_status(:ok)
    expect(JSON.parse(response.body)).to eq('version' => expected_version)
  end
end
