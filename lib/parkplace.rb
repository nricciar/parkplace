require 'rubygems'
require 'camping'
require 'camping/session'
require 'digest/sha1'
require 'base64'
require 'time'
require 'md5'

require 'active_record/acts/nested_set'
ActiveRecord::Base.send :include, ActiveRecord::Acts::NestedSet

Camping.goes :ParkPlace

# Hack for ParkPlace behind a proxy
module ParkPlace::Base
    def URL c='/',*a
      c = R(c, *a) if c.respond_to? :urls
      c = self/c
      hhost = @env.HTTP_X_FORWARDED_HOST.nil? ? @env.HTTP_HOST : @env.HTTP_X_FORWARDED_HOST.to_s
      c = "//"+hhost+c if c[/^\//]
      URI(c)
    end
end

require 'parkplace/errors'
require 'parkplace/helpers'
require 'parkplace/models'
require 'parkplace/controllers'
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
        end
        def serve(host, port)
            require 'mongrel'
            require 'mongrel/camping'
            begin
              require 'gem_plugin'
              gem 'mongrel_upload_progress'
              GemPlugin::Manager.instance.load "mongrel" => GemPlugin::INCLUDE
              require 'patch_upload_progress'
              $PARKPLACE_PROGRESS = true
            rescue LoadError
              puts "-- file upload progress disabled, install mongrel_upload_progress"
            end

            config = Mongrel::Configurator.new( :host => host, :pid_file => File.join(ParkPlace.options.log_dir, "parkplace.#{port}.pid")) do
                if ParkPlace.options.daemon
                  write_pid_file
                  daemonize(:cwd => Dir.pwd, :log_file => File.join(ParkPlace.options.log_dir, "server.log"))
                end

                listener :port => port do
                    uri "/", :handler => Mongrel::Camping::CampingHandler.new(ParkPlace)
                    if $PARKPLACE_PROGRESS
                      uri "/", :handler => plugin('/handlers/upload', { :path_info => '\/control\/buckets\/(.+)' }), :in_front => true
                    end

                    if $PARKPLACE_ACCESSORIES
                      uri "/backup", :handler => BackupHandler.new
                    end
                    uri "/favicon", :handler => Mongrel::Error404Handler.new("")
                    trap("INT") { stop }
                    run
                end
            end

            # save current configuration to last-valid.yaml
            File.open(File.join( ParkPlace.options.parkplace_dir, 'last-valid.yaml' ), 'w') { |f| f.write(YAML::dump(ParkPlace.options)) }
            puts "** ParkPlace is running at http://#{host}:#{port}/"
            puts "** Visit http://#{host}:#{port}/control/ for the control center."
            puts "** Use CTRL+C to stop" unless ParkPlace.options.daemon

            # start our connection with the server if we are running
            # as a slave
            if $PARKPLACE_ACCESSORIES && ParkPlace.options.replication
                trap("INT") { exit }
                sync_manager = SyncManager.new({ :server => ParkPlace.options.replication[:host],
			:username => ParkPlace.options.replication[:username], :secret_key => ParkPlace.options.replication[:secret_key] })

                while true do
                  sync_manager.run
                  sleep 5
                  puts "[#{Time.now}] polling..."
                end
            end
            config.join
        end
    end
end
