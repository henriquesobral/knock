require 'jwt'

module Knock
  class AuthToken
    attr_reader :token
    attr_reader :payload

    def initialize payload: {}, token: nil, verify_options: {}
      if token.present?
        secret = verify_options.key?(:sig_key) && verify_options[:sig_key].present? ? verify_options[:sig_key].call : decode_key
        @payload, _ = JWT.decode token.to_s, secret, true, options.merge(verify_options)
        @token = token
      else
        secret = verify_options.key?(:sig_key) && verify_options[:sig_key].present? ? verify_options[:sig_key].call : secret_key
        @payload = claims.merge(payload)
        @token = JWT.encode @payload,
          secret,
          verify_options[:algorithm].present? ? verify_options[:algorithm] : Knock.token_signature_algorithm
      end
    end

    def entity_for entity_class
      if entity_class.respond_to? :from_token_payload
        entity_class.from_token_payload @payload
      else
        entity_class.find @payload['sub']
      end
    end

    def to_json options = {}
      {jwt: @token}.to_json
    end

  private
    def secret_key
      Knock.token_secret_signature_key.call
    end

    def decode_key
      Knock.token_public_key || secret_key
    end

    def options
      verify_claims.merge({
        algorithm: Knock.token_signature_algorithm
      })
    end

    def claims
      _claims = {}
      _claims[:exp] = token_lifetime if verify_lifetime?
      _claims[:aud] = token_audience if verify_audience?
      _claims[:iat] = token_issued_at
      _claims
    end

    def token_issued_at
      Time.now.to_i
    end
    
    def token_lifetime
      Knock.token_lifetime.from_now.to_i if verify_lifetime?
    end

    def verify_lifetime?
      !Knock.token_lifetime.nil?
    end

    def verify_claims
      {
        aud: token_audience,
        verify_aud: verify_audience?,
        verify_expiration: verify_lifetime?
      }
    end

    def token_audience
      verify_audience? && Knock.token_audience.call
    end

    def verify_audience?
      Knock.token_audience.present?
    end
  end
end
