Puppet::Functions.create_function(:hiera_aws_sm) do
  begin
    require 'json'
  rescue LoadError
    raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install json gem to use hiera-aws-sm backend'
  end
  begin
    require 'aws-sdk-core'
  rescue LoadError
    raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install aws-sdk-core gem to use hiera-aws-sm backend'
  end
  begin
    require 'aws-sdk-secretsmanager'
  rescue LoadError
    raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install aws-sdk-secretsmanager gem to use hiera-aws-sm backend'
  end

  dispatch :lookup_key do
    param 'Variant[String, Numeric]', :key
    param 'Hash', :options
    param 'Puppet::LookupContext', :context
  end

  ##
  # lookup_key
  #
  # Determine whether to lookup a given key in secretsmanager, and if so, return the result of the lookup
  #
  # @param key Key to lookup
  # @param options Options hash
  # @param context Puppet::LookupContext
  def lookup_key(key, options, context)
    # Filter out keys that do not match a regex in `confine_to_keys`, if it's specified
    if confine_keys = options['confine_to_keys']
      raise ArgumentError, '[hiera-aws-sm] confine_to_keys must be an array' unless confine_keys.is_a?(Array)

      begin
        confine_keys = confine_keys.map { |r| Regexp.new(r) }
      rescue StandardError => err
        raise Puppet::DataBinding::LookupError, "[hiera-aws-sm] Failed to create regexp with error #{err}"
      end
      re_match = Regexp.union(confine_keys)
      unless key[re_match] == key
        context.explain { "[hiera-aws-sm] Skipping secrets manager as #{key} doesn't match confine_to_keys" }
        context.not_found
      end
    end

    # Handle prefixes if suplied
    if prefixes = options['prefixes']
      raise ArgumentError, '[hiera-aws-sm] prefixes must be an array' unless prefixes.is_a?(Array)
      if delimiter = options['delimiter']
        raise ArgumentError, '[hiera-aws-sm] delimiter must be a String' unless delimiter.is_a?(String)
      else
        delimiter = '/'
      end

      # Remove trailing delimters from prefixes
      prefixes = prefixes.map { |prefix| (prefix[prefix.length-1] == delimiter) ? prefix[0..prefix.length-2] : prefix }
      # Merge keys and prefixes
      keys = prefixes.map { |prefix| [prefix, key].join(delimiter) }
    else
      keys = [key]
    end

    cache_is_warmed = context.cache_has_key('cache_loaded')

    if !cache_is_warmed
      if warm_caches = options['warm_caches']
        raise ArgumentError, '[hiera-aws-sm] warm_caches must be an array' unless warm_caches.is_a?(Array)
        warm_caches.each do |cache|
          get_secret(cache, options, context)
        end
      end
    end

    # Query SecretsManager for the secret data, stopping once we find a match
    result = nil
    keys.each do |secret_key|
      result = get_secret(secret_key, options, context)
      unless result.nil?
        break
      end
    end

    continue_if_not_found = options['continue_if_not_found'] || false

    if result.nil? and continue_if_not_found
      context.not_found
    end
    result
  end

  ##
  # get_secret
  #
  # Lookup a given key in AWS Secrets Manager
  #
  # @param key Key to lookup
  # @param options Options hash
  # @param context Puppet::LookupContext
  #
  # @return One of Hash, String, (Binary?) depending on the value returned
  # by AWS Secrets Manager. If a secret_binary is present in the response,
  # it is returned directly. If secret_string is set, and can be co-erced
  # into a Hash, it is returned, otherwise a String is returned.
  def get_secret(key, options, context)
    # AWS SM doesn't support colons in secret paths, replace them with periods
    key = key.gsub(/::/, '.')

    if context.cache_has_key(key)
      context.explain { '[hiera-aws-sm] found key in cache' }
      return context.cached_value(key)
    end

    client_opts = {}
    client_opts[:access_key_id] = options['aws_access_key'] if options.key?('aws_access_key')
    client_opts[:secret_access_key] = options['aws_secret_key'] if options.key?('aws_secret_key')
    client_opts[:region] = options['region'] if options.key?('region')

    basic_opts = client_opts

    client_opts[:role_arn] = options['aws_role_arn'] if options.key?('aws_role_arn')
    client_opts[:role_session_name] = options['aws_role_session_name'] if options.key?('aws_role_session_name')
    client_opts[:role_duration_seconds] = options['aws_role_duration_seconds'] if options.key?('aws_role_duration_seconds')

    if client_opts.include?(:role_arn)
      sts = Aws::STS::Client.new(
        region: client_opts[:region],
        access_key_id: client_opts[:access_key_id],
        secret_access_key: client_opts[:secret_access_key]
      )
      time = Time.new
      default_session_name = "puppet-#{time.year}-#{time.month}-#{time.day}-#{time.hour}"
      role_credentials = Aws::AssumeRoleCredentials.new(
        client: sts,
        role_arn: client_opts[:role_arn],
        role_session_name: client_opts[:role_session_name] || default_session_name,
        duration: client_opts[:role_duration_seconds] || 3600
      )
      secretsmanager = Aws::SecretsManager::Client.new(
        region: client_opts[:region],
        credentials: role_credentials
      )
    else
      secretsmanager = Aws::SecretsManager::Client.new(basic_opts)
    end

    response = nil
    secret = nil

    context.explain { "[hiera-aws-sm] Looking up #{key}" }
    begin
      response = secretsmanager.get_secret_value(secret_id: key)
    rescue Aws::SecretsManager::Errors::ResourceNotFoundException => e
      context.explain { "[hiera-aws-sm] No data found for #{key}: #{e.message}" }
    rescue Aws::SecretsManager::Errors::UnrecognizedClientException => e
      raise Puppet::DataBinding::LookupError, "[hiera-aws-sm] Skipping backend. No permission to access #{key}: #{e.message}"
    rescue Aws::SecretsManager::Errors::ServiceError => e
      raise Puppet::DataBinding::LookupError, "[hiera-aws-sm] Skipping backend. Failed to lookup #{key} due to #{e.message}"
    end

    unless response.nil?
      # rubocop:disable Style/NegatedIf
      if !response.secret_binary.nil?
        context.explain { "[hiera-aws-sm] #{key} is a binary" }
        secret = response.secret_binary
      else
        # Do our processing in here
        secret = process_secret_string(response.secret_string, options, context)
      end
      # rubocop:enable Style/NegatedIf
    end

    secret
  end

  ##
  # Process the response secret string by attempting to coerce it
  def process_secret_string(secret_string, _options, context)
    # Attempt to process this string as a JSON object
    begin
      result = JSON.parse(secret_string)
      if result.is_a?(Hash) && _options.key?('warm_caches') && _options.fetch('warm_caches').count > 0
        context.explain { '[hiera-aws-sm] caching hashed data' }
        result.each_key do |k|
          val = result.fetch(k)
          if val.is_a?(String) && val.start_with?('-----BEGIN')
            val = val.gsub('\n', "\n")
          end
          context.cache(k, val)
        end
        if !context.cache_has_key('cache_loaded')
          context.cache('cache_loaded', true)
        end
      end

    rescue JSON::ParserError
      context.explain { '[hiera-aws-sm] Not a hashable result' }
      result = secret_string
    end

    result
  end
end
