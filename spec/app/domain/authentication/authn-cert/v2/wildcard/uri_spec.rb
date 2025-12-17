# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Wildcard::Uri) do
  let(:matcher) { described_class.new }

  def assert_on_failure(response, contained_message)
    expect(response.success?).to be(false)
    expect(response.message).to be_a(message_class)
    expect(response.to_s).to include(contained_message)
  end

  describe '.valid?', type: 'unit' do
    let(:message_class) { LogMessages::Authentication::AuthnCert::URIPatternValidationFailed }

    context 'when pattern is nil' do
      it 'returns false' do
        assert_on_failure(matcher.valid?(nil), "pattern may not be empty")
      end
    end

    context 'when pattern contains double wildcard' do
      it 'returns false' do
        assert_on_failure(matcher.valid?('http://example.com/**/foo'), "double-wildcard not allowed")
      end
    end

    context 'when pattern is a SPIFFE URI with wildcard' do
      it 'returns false' do
        assert_on_failure(matcher.valid?('spiffe://example.com/*/foo'), "wildcards not allowed in SPIFFE URIs")
      end
    end

    context 'when wildcard is in host or userinfo' do
      it 'returns false for wildcard in host' do
        assert_on_failure(matcher.valid?('http://*.example.com/foo'), "wildcards only allowed in path")
      end
      it 'returns false for wildcard in userinfo' do
        assert_on_failure(matcher.valid?('http://user*info@example.com/foo'), "wildcards only allowed in path")
      end
    end

    context 'when wildcard is not a full path segment' do
      it 'returns false for partial segment wildcard' do
        assert_on_failure(matcher.valid?('http://example.com/fo*o/bar'), "wildcard must be entire segment")
      end
    end

    context 'when wildcard is a full path segment' do
      it 'returns true' do
        expect(matcher.valid?('http://example.com/*/bar').success?).to be(true)
      end
    end

    context 'when pattern is a valid URI without wildcards' do
      it 'returns true' do
        expect(matcher.valid?('http://example.com/foo/bar').success?).to be(true)
      end
    end
  end

  describe '.match?', type: 'unit' do
    let(:message_class) { LogMessages::Authentication::AuthnCert::URIPatternMatchingFailed }

    context 'when pattern does not include a wildcard' do
      let(:pattern) { 'http://example.com/foo/bar' }

      it 'returns true for exact match' do
        expect(matcher.match?(pattern, 'http://example.com/foo/bar').success?).to be(true)
      end

      it 'returns false for non-matching candidate' do
        assert_on_failure(matcher.match?(pattern, 'http://example.com/foo/baz'), "path segment mismatch")
        assert_on_failure(matcher.match?(pattern, 'http://example.com/foo'), "path segment mismatch")
      end
    end

    context 'when pattern includes a wildcard in path' do
      let(:pattern) { 'http://example.com/*/bar' }

      it 'matches valid URIs with any single segment in wildcard position' do
        expect(matcher.match?(pattern, 'http://example.com/foo/bar').success?).to be(true)
        expect(matcher.match?(pattern, 'http://example.com/abc/bar').success?).to be(true)
      end

      it 'returns false if wildcard segment is empty or segment count differs' do
        assert_on_failure(matcher.match?(pattern, 'http://example.com//bar'), "path segment mismatch")
        assert_on_failure(matcher.match?(pattern, 'http://example.com/foo/baz/bar'), "path segment mismatch")
      end
    end

    context 'when pattern has multiple wildcard segments' do
      let(:pattern) { 'http://example.com/*/*/bar' }

      it 'matches when both wildcards are filled' do
        expect(matcher.match?(pattern, 'http://example.com/a/b/bar').success?).to be(true)
      end

      it 'returns false if any wildcard segment is empty or segment count differs' do
        assert_on_failure(matcher.match?(pattern, 'http://example.com/a//bar'), "path segment mismatch")
        assert_on_failure(matcher.match?(pattern, 'http://example.com/a/b/c/bar'), "path segment mismatch")
      end
    end

    context 'when pattern or candidate is invalid' do
      it 'returns false' do
        assert_on_failure(matcher.match?('not a uri', 'http://example.com/foo'), "missing scheme or host")
        assert_on_failure(matcher.match?('http://example.com/foo', 'not a uri'), "missing scheme or host")
      end
    end

    context 'when scheme, userinfo, or host do not match' do
      let(:pattern) { 'http://user@example.com/foo/bar' }

      it 'returns false if userinfo does not match' do
        assert_on_failure(matcher.match?(pattern, 'http://example.com/foo/bar'), "userinfo mismatch")
      end

      it 'returns false if host does not match' do
        assert_on_failure(matcher.match?(pattern, 'http://user@other.com/foo/bar'), "host mismatch")
      end

      it 'returns false if scheme does not match' do
        assert_on_failure(matcher.match?(pattern, 'https://user@example.com/foo/bar'), "scheme mismatch")
      end
    end

    context 'wildcard segment matching' do
      it 'matches single segment wildcards' do
        expect(matcher.match?(
          'https://test.org/wiki/*/something/*',
          'https://test.org/wiki/example/something/oof'
        ).success?).to be(true)
      end

      it 'does not match with extra trailing segment' do
        assert_on_failure(
          matcher.match?('https://test.org/wiki/*/something/*', 'https://test.org/wiki/example/something/oof/extra'),
          "path segment mismatch"
        )
      end

      it 'matches exact no-wildcard path' do
        expect(matcher.match?(
          'https://api.example.com/v1/token',
          'https://api.example.com/v1/token'
        ).success?).to be(true)
      end

      it 'fails with different scheme' do
        assert_on_failure(
          matcher.match?('https://api.example.com/v1/token', 'http://api.example.com/v1/token'),
          "scheme mismatch"
        )
      end

      it 'fails with wildcard segment depth mismatch' do
        assert_on_failure(
          matcher.match?('https://service.example.com/*/*', 'https://service.example.com/a/b/c'),
          "path segment mismatch"
        )
      end
    end

    context 'invalid patterns and authority wildcards' do
      it 'rejects partial segment wildcard' do
        assert_on_failure(
          matcher.match?('https://en.wikipedia.org/wiki/ex*mple', 'https://en.wikipedia.org/wiki/example'),
          "path segment mismatch"
        )
      end

      it 'rejects wildcard in authority' do
        assert_on_failure(
          matcher.match?('https://*.example.org/wiki/*', 'https://foo.example.org/wiki/bar'),
          "host mismatch"
        )
      end
    end

    context 'host and path edge cases' do
      it 'matches no path exact host' do
        expect(matcher.match?('https://example.com', 'https://example.com').success?).to be(true)
      end

      it 'rejects candidate with path when pattern has none' do
        assert_on_failure(
          matcher.match?('https://example.com', 'https://example.com/a'),
          "path segment mismatch"
        )
      end

      it 'matches with trailing slash normalization' do
        expect(matcher.match?('https://example.com/api/v1/', 'https://example.com/api/v1').success?).to be(true)
      end
    end

    context 'wildcard segment count' do
      it 'matches all wildcard segments with three segments' do
        expect(matcher.match?('https://example.com/*/*/*', 'https://example.com/a/b/c').success?).to be(true)
      end

      it 'fails with fewer segments' do
        assert_on_failure(
          matcher.match?('https://example.com/*/*/*', 'https://example.com/a/b'),
          "path segment mismatch"
        )
      end

      it 'fails with more segments' do
        assert_on_failure(
          matcher.match?('https://example.com/*/*/*', 'https://example.com/a/b/c/d'),
          "path segment mismatch"
        )
      end
    end

    context 'port and case sensitivity' do
      it 'matches when port is exact' do
        expect(matcher.match?('https://example.com:8443/api/*', 'https://example.com:8443/api/x').success?).to be(true)
      end

      it 'rejects port mismatch' do
        assert_on_failure(
          matcher.match?('https://example.com:8443/api/*', 'https://example.com:443/api/x'),
          "port mismatch"
        )
      end

      it 'rejects missing port when pattern has port' do
        assert_on_failure(
          matcher.match?('https://example.com:8443/api/*', 'https://example.com/api/x'),
          "port mismatch"
        )
      end

      it 'is case-sensitive for host and path' do
        assert_on_failure(
          matcher.match?('https://API.Example.COM/V1/*', 'https://api.example.com/v1/x'),
          "path segment mismatch"
        )
      end

      it 'is case-insensitive for scheme' do
        expect(matcher.match?('HTTPS://example.com/api/*', 'https://example.com/api/x').success?).to be(true)
      end
    end

    context 'query and fragment' do
      it 'ignores query for matching' do
        expect(matcher.match?('https://example.com/api/v1/resource', 'https://example.com/api/v1/resource?x=1&y=2').success?).to be(true)
      end

      it 'ignores fragment for matching' do
        expect(matcher.match?('https://example.com/api/v1/resource', 'https://example.com/api/v1/resource#section').success?).to be(true)
      end
    end

    context 'userinfo and percent encoding' do
      it 'requires userinfo exact match' do
        expect(matcher.match?('https://user:pw@example.com/secure/*', 'https://user:pw@example.com/secure/a').success?).to be(true)
      end

      it 'fails if candidate missing userinfo' do
        assert_on_failure(
          matcher.match?('https://user:pw@example.com/secure/*', 'https://example.com/secure/a'),
          "userinfo mismatch"
        )
      end

      it 'matches percent-encoded segment exactly' do
        expect(matcher.match?('https://example.com/a%20b/*', 'https://example.com/a%20b/x').success?).to be(true)
      end

      it 'fails with different percent encoding' do
        assert_on_failure(
          matcher.match?('https://example.com/a%20b/*', 'https://example.com/a%2Bb/x'),
          "path segment mismatch"
        )
      end

      it 'does not match decoded form for percent-encoded segment' do
        assert_on_failure(
          matcher.match?('https://example.com/a%20b/*', 'https://example.com/a b/x'),
          "path segment mismatch"
        )
      end

      it 'does not match decoded form for url encoded segment' do
        assert_on_failure(
          matcher.match?('https://example.org/*/a%20b', 'https://example.org/*/a b'),
          "path segment mismatch"
        )
      end
    end

    context 'empty segments and double slashes' do
      it 'does not match empty candidate segment for wildcard' do
        assert_on_failure(
          matcher.match?('https://example.com/*/b', 'https://example.com//b'),
          "path segment mismatch"
        )
      end

      it 'matches empty segments in path' do
        expect(matcher.match?('https://example.com/*//b', 'https://example.com/a//b').success?).to be(true)
      end

      it 'does not match candidate without double slash when pattern has it' do
        assert_on_failure(
          matcher.match?('https://example.com//*/a', 'https://example.com/test/a'),
          "path segment mismatch"
        )
      end

      it 'matches interior empty segment' do
        expect(matcher.match?('https://example.com//*/a', 'https://example.com//foo/a').success?).to be(true)
      end

      it 'does not match empty candidate segment for wildcard in interior' do
        assert_on_failure(
          matcher.match?('https://test.example.com/path/*/example', 'https://test.example.com/path//example'),
          "path segment mismatch"
        )
      end
    end

    context 'invalid patterns' do
      it 'rejects wildcard in scheme' do
        assert_on_failure(
          matcher.match?('htt*ps://example.com/x', 'https://example.com/x'),
          "invalid URI format"
        )
      end

      it 'rejects wildcard in host label' do
        assert_on_failure(
          matcher.match?('https://exa*mple.com/x', 'https://example.com/x'),
          "host mismatch"
        )
      end

      it 'rejects partial path segment wildcard' do
        assert_on_failure(
          matcher.match?('https://example.com/exa*mple', 'https://example.com/example'),
          "path segment mismatch"
        )
      end

      it 'rejects file scheme (no host)' do
        assert_on_failure(
          matcher.match?('file:///etc/hosts', 'file:///etc/hosts'),
          "missing scheme or host"
        )
      end
    end

    context 'literal and regex characters' do
      it 'does not match with only literals mismatch' do
        assert_on_failure(
          matcher.match?('https://example.com/a/b/c', 'https://example.com/a/b/x'),
          "path segment mismatch"
        )
      end

      it 'treats regex characters as literal in URI path' do
        expect(matcher.match?('https://example.com/api/v[1-9]/resource', 'https://example.com/api/v[1-9]/resource').success?).to be(true)
      end

      it 'does not support regex patterns in URI' do
        assert_on_failure(
          matcher.match?('https://example.com/api/v\\d+/resource', 'https://example.com/api/v1/resource'),
          "path segment mismatch"
        )
        assert_on_failure(
          matcher.match?('https://example.com/api/v\\d+/resource', 'https://example.com/api/v2/resource'),
          "path segment mismatch"
        )
      end
    end

    context 'pattern without slash and trailing slash candidate' do
      it 'matches candidate with trailing slash' do
        expect(matcher.match?('https://example.com', 'https://example.com/').success?).to be(true)
      end
    end

    context 'case sensitivity' do
      it 'matches with scheme and host case insensitively' do
        expect(matcher.match?('https://example.com/api/*', 'HTTPS://example.com/api/x').success?).to be(true)
        expect(matcher.match?('https://example.com/api/*', 'https://EXAMPLE.COM/api/x').success?).to be(true)
      end

      it 'matches with path and userinfo case sensitively' do
        assert_on_failure(
          matcher.match?('https://user:password@example.com/api/*', 'https://User:Password@example.com/api/resource'),
          "userinfo mismatch"
        )
        assert_on_failure(
          matcher.match?('https://user:password@example.com/api/*', 'https://user:password@example.com/API/resource'),
          "path segment mismatch"
        )
      end
    end
  end
end
