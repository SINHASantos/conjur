# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Wildcard::Uri) do
  let(:matcher) { described_class }

  describe '.valid?', type: 'unit' do
    context 'when pattern is nil' do
      it 'returns false' do
        expect(matcher.valid?(nil)).to be(false)
      end
    end

    context 'when pattern contains double wildcard' do
      it 'returns false' do
        expect(matcher.valid?('http://example.com/**/foo')).to be(false)
      end
    end

    context 'when pattern is a SPIFFE URI with wildcard' do
      it 'returns false' do
        expect(matcher.valid?('spiffe://example.com/*/foo')).to be(false)
      end
    end

    context 'when wildcard is in host or userinfo' do
      it 'returns false for wildcard in host' do
        expect(matcher.valid?('http://*.example.com/foo')).to be(false)
      end
      it 'returns false for wildcard in userinfo' do
        expect(matcher.valid?('http://user*info@example.com/foo')).to be(false)
      end
    end

    context 'when wildcard is not a full path segment' do
      it 'returns false for partial segment wildcard' do
        expect(matcher.valid?('http://example.com/fo*o/bar')).to be(false)
      end
    end

    context 'when wildcard is a full path segment' do
      it 'returns true' do
        expect(matcher.valid?('http://example.com/*/bar')).to be(true)
      end
    end

    context 'when pattern is a valid URI without wildcards' do
      it 'returns true' do
        expect(matcher.valid?('http://example.com/foo/bar')).to be(true)
      end
    end
  end

  describe '.match?', type: 'unit' do
    context 'when pattern does not include a wildcard' do
      let(:pattern) { 'http://example.com/foo/bar' }

      it 'returns true for exact match' do
        expect(matcher.match?(pattern, 'http://example.com/foo/bar')).to be(true)
      end

      it 'returns false for non-matching candidate' do
        expect(matcher.match?(pattern, 'http://example.com/foo/baz')).to be(false)
        expect(matcher.match?(pattern, 'http://example.com/foo')).to be(false)
      end
    end

    context 'when pattern includes a wildcard in path' do
      let(:pattern) { 'http://example.com/*/bar' }

      it 'matches valid URIs with any single segment in wildcard position' do
        expect(matcher.match?(pattern, 'http://example.com/foo/bar')).to be(true)
        expect(matcher.match?(pattern, 'http://example.com/abc/bar')).to be(true)
      end

      it 'returns false if wildcard segment is empty or segment count differs' do
        expect(matcher.match?(pattern, 'http://example.com//bar')).to be(false)
        expect(matcher.match?(pattern, 'http://example.com/foo/baz/bar')).to be(false)
      end
    end

    context 'when pattern has multiple wildcard segments' do
      let(:pattern) { 'http://example.com/*/*/bar' }

      it 'matches when both wildcards are filled' do
        expect(matcher.match?(pattern, 'http://example.com/a/b/bar')).to be(true)
      end

      it 'returns false if any wildcard segment is empty or segment count differs' do
        expect(matcher.match?(pattern, 'http://example.com/a//bar')).to be(false)
        expect(matcher.match?(pattern, 'http://example.com/a/b/c/bar')).to be(false)
      end
    end

    context 'when pattern or candidate is invalid' do
      it 'returns false' do
        expect(matcher.match?('not a uri', 'http://example.com/foo')).to be(false)
        expect(matcher.match?('http://example.com/foo', 'not a uri')).to be(false)
      end
    end

    context 'when scheme, userinfo, or host do not match' do
      let(:pattern) { 'http://user@example.com/foo/bar' }

      it 'returns false if userinfo does not match' do
        expect(matcher.match?(pattern, 'http://other@example.com/foo/bar')).to be(false)
      end

      it 'returns false if host does not match' do
        expect(matcher.match?(pattern, 'http://user@other.com/foo/bar')).to be(false)
      end

      it 'returns false if scheme does not match' do
        expect(matcher.match?(pattern, 'https://user@example.com/foo/bar')).to be(false)
      end
    end

    context 'wildcard segment matching' do
      it 'matches single segment wildcards' do
        expect(matcher.match?('https://test.org/wiki/*/something/*', 'https://test.org/wiki/example/something/oof')).to be(true)
      end

      it 'does not match with extra trailing segment' do
        expect(matcher.match?('https://test.org/wiki/*/something/*', 'https://test.org/wiki/example/something/another/test')).to be(false)
      end

      it 'matches exact no-wildcard path' do
        expect(matcher.match?('https://api.example.com/v1/token', 'https://api.example.com/v1/token')).to be(true)
      end

      it 'fails with different scheme' do
        expect(matcher.match?('https://api.example.com/v1/token', 'http://api.example.com/v1/token')).to be(false)
      end

      it 'fails with wildcard segment depth mismatch' do
        expect(matcher.match?('https://service.example.com/*/*', 'https://service.example.com/a/b/c')).to be(false)
      end
    end

    context 'invalid patterns and authority wildcards' do
      it 'rejects partial segment wildcard' do
        expect(matcher.match?('https://en.wikipedia.org/wiki/ex*mple', 'https://en.wikipedia.org/wiki/example')).to be(false)
      end

      it 'rejects wildcard in authority' do
        expect(matcher.match?('https://*.example.org/wiki/*', 'https://foo.example.org/wiki/bar')).to be(false)
      end
    end

    context 'host and path edge cases' do
      it 'matches no path exact host' do
        expect(matcher.match?('https://example.com', 'https://example.com')).to be(true)
      end

      it 'rejects candidate with path when pattern has none' do
        expect(matcher.match?('https://example.com', 'https://example.com/a')).to be(false)
      end

      it 'matches with trailing slash normalization' do
        expect(matcher.match?('https://example.com/api/v1/', 'https://example.com/api/v1')).to be(true)
      end
    end

    context 'wildcard segment count' do
      it 'matches all wildcard segments with three segments' do
        expect(matcher.match?('https://example.com/*/*/*', 'https://example.com/a/b/c')).to be(true)
      end

      it 'fails with fewer segments' do
        expect(matcher.match?('https://example.com/*/*/*', 'https://example.com/a/b')).to be(false)
      end

      it 'fails with more segments' do
        expect(matcher.match?('https://example.com/*/*/*', 'https://example.com/a/b/c/d')).to be(false)
      end
    end

    context 'port and case sensitivity' do
      it 'matches when port is exact' do
        expect(matcher.match?('https://example.com:8443/api/*', 'https://example.com:8443/api/x')).to be(true)
      end

      it 'rejects port mismatch' do
        expect(matcher.match?('https://example.com:8443/api/*', 'https://example.com:443/api/x')).to be(false)
      end

      it 'rejects missing port when pattern has port' do
        expect(matcher.match?('https://example.com:8443/api/*', 'https://example.com/api/x')).to be(false)
      end

      it 'is case-sensitive for host and path' do
        expect(matcher.match?('https://API.Example.COM/V1/*', 'https://api.example.com/v1/x')).to be(false)
      end

      it 'is case-insensitive for scheme' do
        expect(matcher.match?('HTTPS://example.com/api/*', 'https://example.com/api/x')).to be(true)
      end
    end

    context 'query and fragment' do
      it 'ignores query for matching' do
        expect(matcher.match?('https://example.com/api/v1/resource', 'https://example.com/api/v1/resource?x=1&y=2')).to be(true)
      end

      it 'ignores fragment for matching' do
        expect(matcher.match?('https://example.com/api/v1/resource', 'https://example.com/api/v1/resource#section')).to be(true)
      end
    end

    context 'userinfo and percent encoding' do
      it 'requires userinfo exact match' do
        expect(matcher.match?('https://user:pw@example.com/secure/*', 'https://user:pw@example.com/secure/a')).to be(true)
      end

      it 'fails if candidate missing userinfo' do
        expect(matcher.match?('https://user:pw@example.com/secure/*', 'https://example.com/secure/a')).to be(false)
      end

      it 'matches percent-encoded segment exactly' do
        expect(matcher.match?('https://example.com/a%20b/*', 'https://example.com/a%20b/x')).to be(true)
      end

      it 'fails with different percent encoding' do
        expect(matcher.match?('https://example.com/a%20b/*', 'https://example.com/a%2Bb/x')).to be(false)
      end

      it 'does not match decoded form for percent-encoded segment' do
        expect(matcher.match?('https://example.com/a%20b/*', 'https://example.com/a b/x')).to be(false)
      end

      it 'does not match decoded form for url encoded segment' do
        expect(matcher.match?('https://example.org/*/a%20b', 'https://example.org/*/a b')).to be(false)
      end
    end

    context 'empty segments and double slashes' do
      it 'does not match empty candidate segment for wildcard' do
        expect(matcher.match?('https://example.com/*/b', 'https://example.com//b')).to be(false)
      end

      it 'matches empty segments in path' do
        expect(matcher.match?('https://example.com/*//b', 'https://example.com/a//b')).to be(true)
      end

      it 'does not match candidate without double slash when pattern has it' do
        expect(matcher.match?('https://example.com//*/a', 'https://example.com/test/a')).to be(false)
      end

      it 'matches interior empty segment' do
        expect(matcher.match?('https://example.com//*/a', 'https://example.com//foo/a')).to be(true)
      end

      it 'does not match empty candidate segment for wildcard in interior' do
        expect(matcher.match?('https://test.example.com/path/*/example', 'https://test.example.com/path//example')).to be(false)
      end
    end

    context 'invalid patterns' do
      it 'rejects wildcard in scheme' do
        expect(matcher.match?('htt*ps://example.com/x', 'https://example.com/x')).to be(false)
      end

      it 'rejects wildcard in host label' do
        expect(matcher.match?('https://exa*mple.com/x', 'https://example.com/x')).to be(false)
      end

      it 'rejects partial path segment wildcard' do
        expect(matcher.match?('https://example.com/exa*mple', 'https://example.com/example')).to be(false)
      end

      it 'rejects file scheme (no host)' do
        expect(matcher.match?('file:///etc/hosts', 'file:///etc/hosts')).to be(false)
      end
    end

    context 'literal and regex characters' do
      it 'does not match with only literals mismatch' do
        expect(matcher.match?('https://example.com/a/b/c', 'https://example.com/a/b/x')).to be(false)
      end

      it 'treats regex characters as literal in URI path' do
        expect(matcher.match?('https://example.com/api/v[1-9]/resource', 'https://example.com/api/v[1-9]/resource')).to be(true)
      end

      it 'does not support regex patterns in URI' do
        expect(matcher.match?('https://example.com/api/v\\d+/resource', 'https://example.com/api/v1/resource')).to be(false)
        expect(matcher.match?('https://example.com/api/v\\d+/resource', 'https://example.com/api/v2/resource')).to be(false)
      end
    end

    context 'pattern without slash and trailing slash candidate' do
      it 'matches candidate with trailing slash' do
        expect(matcher.match?('https://example.com', 'https://example.com/')).to be(true)
      end
    end

    context 'host case mismatch' do
      it 'fails with host case mismatch' do
        expect(matcher.match?('https://Api.Example.Com/x/*', 'https://api.example.com/x/a')).to be(false)
      end
    end
  end
end
