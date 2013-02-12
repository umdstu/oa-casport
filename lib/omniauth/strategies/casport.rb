require 'omniauth'
require 'httparty'
require 'redis'
require 'uri'
require 'yaml'

module OmniAuth
  module Strategies
    #
    # Authentication to CASPORT
    #
    # @example Basic Usage
    #
    #  use OmniAuth::Strategies::Casport, {
    #    :setup       => true
    #  }
    # @example Full Options Usage
    #
    #  use OmniAuth::Strategies::Casport, {
    #    :setup         => true,
    #    :cas_server    => 'http://cas.slkdemos.com/users/',
    #    :format        => 'json', 'xml', 'html', etc. || Defaults to 'xml'
    #    :format_header => 'application/xml',
    #    :ssl_ca_file   => 'path/to/ca_file.crt',
    #    :pem_cert      => '/path/to/cert.pem',
    #    :pem_cert_pass => 'keep it secret, keep it safe.',
    #    :redis_options => 'disabled' or options_hash || Defaults to {:host => '127.0.0.1', :port => 6739}
    #  }
    class Casport

      include OmniAuth::Strategy
      include HTTParty
      
      args[:setup, :ssl_ca_file, :pem_cert, :cert_password, :cas_server]

      option :name,         'casport'
      option :dn,           nil
      option :full_name,    nil
      option :last_name,    nil
      option :uid,          nil
      option :first_name,   ""
      option :display_name, ""
      option :title,        ""
      option :permission,   ""
      option :email,        ""
      option :uid_field,    :uid


      uid do {
        user['dn']
      } end

      info do {
        :name => user['full_name']
        :email => user['email']
      } end

      extra do {
        'raw_info' => raw_info
      } end

      def raw_info
        user
      end



      def request_phase
        if options.uid.nil? || options.uid.empty?
          e = "No UID set in request.env['omniauth.strategy'].options[:uid]"
          fail(!uid_not_found, e)
          raise e
        end

        Casport.setup_httparty(options)
        redirect("#{OmniAuth.config.full_host}#{callback_path}")
      end

      def callback_phase
        begin
          super
        rescue => e
          redirect(request_path)
          fail(:invalid_credentials, e)
        end

        super
      end

      def self.setup_httparty(opts)
        format opts[:format].to_sym
        headers 'Accept'               => opts.format_header
        headers 'Content-Type'         => opts.format_header
        headers 'X-XSRF-UseProtection' => 'false' if opts.format == 'json'
        if opts.ssl_ca_file
          ssl_ca_file opts.ssl_ca_file
          if opts.pem_cert_pass
            pem File.read(opts.pem_cert), opts.pem_cert_pass
          else
            pem File.read(opts.pem_cert)
          end
        end
      end
      
      def user
        
        if options.uid.include?('/') or options.uid.include?(',')
          options.uid = options.uid.gsub('/',',').split(',').reject{|array| array.all? {|el| el.nil? || el.strip.empty? }}
          options.uid = options.uid.reverse if @options[:uid].first.downcase.include? 'c='
          options.uid = options.join ','
        end
      
        begin
          raise Errno::ECONNREFUSED if options.redis_options == 'disabled'
          cache = options.redis_options.nil? ? Redis.new : Redis.new(options.redis_options)
          unless @user = (cache.get options.uid)
            get_user
            if @user
              cache.set options.uid, @user.to_yaml
              cache.expire options.uid, 1440
            end
          else
            @user = YAML::load(@user)
          end
        rescue Errno::ECONNREFUSED => e
          get_user
        end
        @user
      end

      def get_user
        return if @user
        url = URI.escape("#{options.cas_server}/#{options.uid}.#{options.format}")
        response = Casport.get(url)
        if response.success?
          @user = response.parsed_response
        else
          @user = nil
        end
      end
      
    end
  end
end
