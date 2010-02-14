require 'rubygems'
require 'camping'
require 'camping/session'
require 'digest/sha1'
require 'base64'
require 'time'
require 'md5'
require 'rack'

require 'active_record/acts/nested_set'
ActiveRecord::Base.send :include, ActiveRecord::Acts::NestedSet

Camping.goes :ParkPlace

require 'parkplace/errors'
require 'parkplace/helpers'
require 'parkplace/models'
require 'parkplace/controllers'
begin
  require 'gem_plugin'
  gem 'mongrel_upload_progress'
  GemPlugin::Manager.instance.load "mongrel" => GemPlugin::INCLUDE
  require 'parkplace/upload_progress'
  Rack::Handler.register 'mongrel', 'Rack::Handler::MongrelUploadProgress'
  Rack::Handler.register 'mongrel_no_upload_progress', 'Rack::Handler::Mongrel'
rescue LoadError
  puts "-- Unable to load mongrel_upload_progress, no fancy upload progress."
end

if $PARKPLACE_ACCESSORIES
  require 'parkplace/sync_manager'
  require 'parkplace/backup_manager'
  require 'parkplace/control'
  begin
    require 'exifr'
    puts "-- EXIFR found, JPEG metadata enabled."
  rescue LoadError
    puts "-- EXIFR not found, JPEG metadata disabled."
  end
end
begin
    require "git"
    puts "-- Git support found, versioning support enabled."
rescue LoadError
    puts "-- Git support not found, versioning support disabled."
end
begin
    require 'parkplace/torrent'
    puts "-- RubyTorrent found, torrent support is turned on."
    puts "-- TORRENT SUPPORT IS EXTREMELY EXPERIMENTAL -- WHAT I MEAN IS: IT PROBABLY DOESN'T WORK."
rescue LoadError
    puts "-- No RubyTorrent found, torrent support disbled."
end

require 'parkplace/s3'

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

    class << self

        def create
            v = 0.0
            v = 1.0 if Models::Bucket.table_exists?
            Camping::Models::Session.create_schema
            Models.create_schema :assume => v
            puts "** No users found, creating the `admin' user." if v == 0.0
            admin = Models::User.find_by_login 'admin'
            if admin && admin.password == hmac_sha1( Models::SetupParkPlace::DEFAULT_PASSWORD, admin.secret )
              puts "** Please login in with `admin' and password `#{Models::SetupParkPlace::DEFAULT_PASSWORD}'"
              puts "** You should change the default password for the admin at soonest chance!"
            end
        end
        def default_options
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

        def options
          @options ||= default_options
        end

        def options=(val)
          @options = val
        end

        def config(options)
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
            Models::Base.establish_connection(options.database)
            Models::Base.logger = Logger.new('camping.log') if $DEBUG
        end

        def call(env)
          env["PATH_INFO"] ||= ""
          env["SCRIPT_NAME"] ||= ""
          env["HTTP_CONTENT_LENGTH"] ||= env["CONTENT_LENGTH"]
          env["HTTP_CONTENT_TYPE"] ||= env["CONTENT_TYPE"]
          controller = run(env['rack.input'], env)
          h = controller.headers
          h.each_pair do |k,v|
            if v.kind_of? URI
              h[k] = v.to_s
            end
          end

          # mongrel gets upset over headers with nil values
          controller.headers.delete_if { |x,y| y.nil? }

          if !ParkPlace.options.use_x_sendfile && controller.headers.include?('X-Sendfile') && File.exists?(controller.headers['X-Sendfile'])
            return [200,controller.headers,File.read(controller.headers.delete('X-Sendfile'))]
          end

          [controller.status, controller.headers, ["#{controller.body}"]]
        end

        def daemonize
          if RUBY_VERSION < "1.9"
            exit if fork
            Process.setsid
            exit if fork
            Dir.chdir "/"
            ::File.umask 0000
            STDIN.reopen "/dev/null"
            STDOUT.reopen "/dev/null", "a"
            STDERR.reopen "/dev/null", "a"
          else
            Process.daemon
          end
        end

        def write_pid
          ::File.open(options.pid_file, 'w'){ |f| f.write("#{Process.pid}") }
          at_exit { ::File.delete(options.pid_file) if ::File.exist?(options.pid_file) }
        end

        # mostly taken from Rack::Handler but we override the default
        # mongrel handler if mongrel_upload_progress is installed and
        # Rack::Handler.default messes that up
        def server
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

        def serve(host, port)
          app, config = Rack::Builder.parse_file(options.rack_config.nil? ? "config.ru" : options.rack_config)
          File.open(File.join( ParkPlace.options.parkplace_dir, 'last-valid.yaml' ), 'w') { |f| f.write(YAML::dump(ParkPlace.options)) }

          # start our connection with the server if we are running
          # as a slave
          if $PARKPLACE_ACCESSORIES && ParkPlace.options.replication
             trap("INT") { exit }
             sync_manager = SyncManager.new({ :server => ParkPlace.options.replication[:host],
               :username => ParkPlace.options.replication[:username], :secret_key => ParkPlace.options.replication[:secret_key] })

             Thread.new {
               while true do
                 sync_manager.run
                 sleep 5
                 puts "[#{Time.now}] sync_manager: polling..." if ParkPlace.options.verbose
               end
             }
          end

          daemonize if ParkPlace.options.daemon
          write_pid if ParkPlace.options.pid_file

          ParkPlace.server.run app, :Port => port, :Host => host
        end
    end
end

include ParkPlace
