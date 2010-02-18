require 'rubygems'
require 'digest/sha1'
require 'base64'
require 'time'
require 'md5'
require 'rack'

require 'active_support'
require 'active_record'

require 'active_record/acts/nested_set'
ActiveRecord::Base.send :include, ActiveRecord::Acts::NestedSet

#require 'parkplace/addons'
require 'parkplace/errors'
require 'parkplace/helpers'
require 'active_record/acts/nested_set'
require 'parkplace/bit'
require 'parkplace/user'
require 'parkplace/controllers'
require 'parkplace/sync_manager'
require 'parkplace/backup_manager'
#require 'parkplace/control'
require 'parkplace/s3'

DEFAULT_PASSWORD = 'pass@word1'
DEFAULT_SECRET = 'OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV'

module ParkPlace
    VERSION = "0.7"
    BUFSIZE = (4 * 1024)
    STORAGE_PATH = File.join(Dir.pwd, 'storage')
    STATIC_PATH = File.expand_path('../static', File.dirname(__FILE__))
    RESOURCE_TYPES = %w[acl torrent versioning]
    CANNED_ACLS = {
        'private' => 0600,
        'public-read' => 0644,
        'public-read-write' => 0666,
        'authenticated-read' => 0640,
        'authenticated-read-write' => 0660
    }
    READABLE = 0004
    WRITABLE = 0002
    READABLE_BY_AUTH = 0040
    WRITABLE_BY_AUTH = 0020

    class Base

        def self.create
return
            v = 0.0
            v = 1.0 if Models::Bucket.table_exists?
            Models.create_schema :assume => v
            puts "** No users found, creating the `admin' user." if v == 0.0
            admin = Models::User.find_by_login 'admin'
            if admin && admin.password == hmac_sha1( Models::SetupParkPlace::DEFAULT_PASSWORD, admin.secret )
              puts "** Please login in with `admin' and password `#{Models::SetupParkPlace::DEFAULT_PASSWORD}'"
              puts "** You should change the default password for the admin at soonest chance!"
            end
        end

        def self.default_options
            require 'ostruct'
            options = OpenStruct.new
            if options.parkplace_dir.nil?
                homes = []
                homes << [ENV['HOME'], File.join( ENV['HOME'], '.parkplace' )] if ENV['HOME']
                homes << [ENV['APPDATA'], File.join( ENV['APPDATA'], 'ParkPlace' )] if ENV['APPDATA']
                homes.each do |home_top, home_dir|
                    next unless home_top
                    if File.exists? home_top
                        options.parkplace_dir = home_dir
                        break
                    end
                end
            end
            options
        end

        def self.options
          @options ||= default_options
        end

        def self.options=(val)
          @options = val
        end

        def self.config(options)
            require 'ftools'
            require 'yaml'
            abort "** No home directory found, please say the directory when you run #$O." unless options.parkplace_dir
            File.makedirs( options.parkplace_dir )
            conf = File.join( options.parkplace_dir, 'config.yaml' )
            if File.exists? conf
                puts "** Using config from #{conf}"
                YAML.load_file(conf).marshal_dump.each { |k,v| options.__send__("#{k}=", v) if options.__send__(k).nil? }
            end
            options.storage_dir = File.expand_path(options.storage_dir || 'storage', options.parkplace_dir)
            FileUtils.mkdir_p options.storage_dir unless File.exists?(options.storage_dir)
            options.log_dir = File.expand_path(options.log_dir || 'log', options.parkplace_dir)
            FileUtils.mkdir_p(options.log_dir) unless File.exists?(options.log_dir)
            options.database ||= {:adapter => 'sqlite3', :database => File.join(options.parkplace_dir, (!options.replication.nil? && 
		options.replication[:enabled] ? 'park-slave.db' : 'park.db'))}
            if options.database[:adapter] == 'sqlite3'
                begin
                    require 'sqlite3_api'
                rescue LoadError
                    puts "!! Your SQLite3 adapter isn't a compiled extension."
                    abort "!! Please check out http://code.whytheluckystiff.net/camping/wiki/BeAlertWhenOnSqlite3 for tips."
                end
            end
            ParkPlace::STORAGE_PATH.replace options.storage_dir
            ActiveRecord::Base.table_name_prefix = 'parkplace_'
            ActiveRecord::Base.establish_connection(options.database)
            ActiveRecord::Base.logger = Logger.new('debug.log') if $DEBUG
            create
        end

        def self.add_url(path)
        
        end

        def self.call(env)
          # apparently if we do not call this we will run out
          # of database connections
          ActiveRecord::Base.verify_active_connections!

          env["PATH_INFO"] ||= ""
          env["SCRIPT_NAME"] ||= ""
          env["HTTP_CONTENT_LENGTH"] ||= env["CONTENT_LENGTH"]
          env["HTTP_CONTENT_TYPE"] ||= env["CONTENT_TYPE"]
          env["HTTP_HOST"] = env["HTTP_X_FORWARDED_HOST"] unless env["HTTP_X_FORWARDED_HOST"].nil?

          code = nil
          status = 200
          headers = {}
          body = []

          @request = Rack::Request.new(env)
          ParkPlace::Controllers.r.each do |route|
            begin
              route.urls.each do |url|
                if env["REQUEST_PATH"] =~ /^#{url}\/?$/ 
                  request = route.new
                  if env["HTTP_AUTHORIZATION"]
                    meta,amz,user = authenticate_user(@request)
                    request.extend(ParkPlace::S3)
                    request.instance_variable_set(:@user, user)
                    request.instance_variable_set(:@meta, meta)
                    request.instance_variable_set(:@amz, amz)
                  end
                  request.instance_variable_set(:@env, env)
                  request.instance_variable_set(:@input, @request.params)
                  call = (env["REQUEST_METHOD"] || "GET").downcase
                  status, headers, body = request.send(*([call] + $~.captures)) if request.respond_to? call
                end
              end
            rescue ParkPlace::ServiceError => e
              code = e.code
              status = e.status
              body = e.message
              break unless e.status == 404
            end
          end

	  # mongrel gets upset over headers with nil values
	  headers.delete_if { |x,y| y.nil? }

          if !options.use_x_sendfile && headers.include?('X-Sendfile') && File.exists?(headers['X-Sendfile'])
	    body = File.open(headers.delete('X-Sendfile'))
          end

          unless env["HTTP_AUTHORIZATION"] && status >= 400 && code
  	    [status, headers, body]
          else
            xml status do |x|
              x.Error do
                x.Code code
                x.Message body
                x.Resource env['PATH_INFO']
                x.RequestId Time.now.to_i
              end
            end
          end
        end

    def self.authenticate_user(request)
      env = request.env
      meta, amz = {}, {}
      env.each do |k,v|
        k = k.downcase.gsub('_', '-')
        amz[$1] = v.strip if k =~ /^http-x-amz-([-\w]+)$/
        meta[$1] = v if k =~ /^http-x-amz-meta-([-\w]+)$/
      end
        auth, key_s, secret_s = *env['HTTP_AUTHORIZATION'].to_s.match(/^AWS (\w+):(.+)$/)
        date_s = env['HTTP_X_AMZ_DATE'] || env['HTTP_DATE']
        if request.params.has_key?('Signature') and Time.at(request['Expires'].to_i) >= Time.now
          key_s, secret_s, date_s = request['AWSAccessKeyId'], request['Signature'], request['Expires']
        end
        uri = env['PATH_INFO']
        uri += "?" + env['QUERY_STRING'] if ParkPlace::RESOURCE_TYPES.include?(env['QUERY_STRING'])
        canonical = [env['REQUEST_METHOD'], env['HTTP_CONTENT_MD5'], env['HTTP_CONTENT_TYPE'],
          date_s, uri]
        amz.sort.each do |k, v|
          canonical[-1,0] = "x-amz-#{k}:#{v}"
        end
        user = ParkPlace::Models::User.find_by_key key_s

        if (user and secret_s != hmac_sha1(user.secret, canonical.map{|v|v.to_s.strip} * "\n")) || (user and user.deleted == 1)
          raise BadAuthentication
        end
      [meta,amz,user]
    end

        def self.daemonize
          if RUBY_VERSION < "1.9"
            exit if fork
            Process.setsid
            exit if fork
            Dir.chdir File.expand_path(File.dirname(__FILE__))
            ::File.umask 0000
            STDIN.reopen "/dev/null"
            STDOUT.reopen "/dev/null", "a"
            STDERR.reopen "/dev/null", "a"
          else
            Process.daemon
          end
        end

        def self.write(data)
          logger.write(data)
          logger.flush
        end

        def self.logger
          @file ||= File.new(File.join(options.log_dir, "parkplace.log"),'a')
        end

        def self.write_pid
          ::File.open(options.pid_file, 'w'){ |f| f.write("#{Process.pid}") }
          at_exit { ::File.delete(options.pid_file) if ::File.exist?(options.pid_file) }
        end

        # mostly taken from Rack::Handler but we override the default
        # mongrel handler if mongrel_upload_progress is installed and
        # Rack::Handler.default messes that up
        def self.server
          # return handler specified by options
          return Rack::Handler.get(options.server) unless options.server.nil?

          # Guess.
          if ENV.include?("PHP_FCGI_CHILDREN")
            # We already speak FastCGI
            options.delete :File
            options.delete :Port
 
            Rack::Handler::FastCGI
          elsif ENV.include?("REQUEST_METHOD")
            Rack::Handler::CGI
          else
            begin
              # Lookup the correct handler for mongrel instead of
              # assuming it's Rack::Handler::Mongrel
              Rack::Handler.get('mongrel')
            rescue LoadError => e
              Rack::Handler::WEBrick
            end
          end
        end

        def self.serve(host, port)
          app, config = Rack::Builder.parse_file(options.rack_config.nil? ? "config.ru" : options.rack_config)
          File.open(File.join( options.parkplace_dir, 'last-valid.yaml' ), 'w') { |f| f.write(YAML::dump(options)) }

          # start our connection with the server if we are running
          # as a slave
          if $PARKPLACE_ACCESSORIES && options.replication
             trap("INT") { exit }
             sync_manager = SyncManager.new({ :server => options.replication[:host],
               :username => options.replication[:username], :secret_key => options.replication[:secret_key] })

             Thread.new {
               while true do
                 sync_manager.run
                 sleep 5
                 puts "[#{Time.now}] sync_manager: polling..." if options.verbose
               end
             }
          end

          daemonize if options.daemon
          write_pid if options.pid_file

          server.run app, :Port => port, :Host => host
        end

    end

end

include ParkPlace
