require 'parkplace/thread_pool'
begin
  require 'curb'
rescue LoadError
  begin
    require 'rfuzz/session'
  rescue LoadError
    require 'net/http'
    puts "-- rfuzz and curb not found falling back on net/http (expect higher CPU usage, and more crashes)"
  end
end

module ParkPlace

  class SyncManager

    attr_accessor :server, :port, :secret_key, :username

    def initialize(options = {})
      host_check = options[:server].split(":")
      self.server = host_check.first
      self.port = host_check.size == 1 ? 80 : host_check[1].to_i
      self.secret_key = options[:secret_key].nil? ? 'OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV' : options[:secret_key]
      self.username = options[:username].nil? ? 'admin' : options[:username]
      @pool = ThreadPool.new(10)
    end

    def auth_header(path,modified=nil)
      request_key = MD5.md5("#{self.secret_key}:#{path}:#{modified}").hexdigest
      "#{self.username}:#{request_key}"
    end

    def get_file(path,ifmodified=nil,save_as=nil)
      default_headers = { 'Authorization' => auth_header(path,ifmodified) }
      if defined?(Curl)
        if save_as.nil?
          client = Curl::Easy.new("http://#{self.server}:#{self.port}#{path}")
          client.headers = default_headers.merge(ifmodified.nil? ? {} : { 'If-Modified-Since' => ifmodified })
          client.perform
          yield client.body_str
        else
          Curl::Easy.download("http://#{self.server}:#{self.port}#{path}",save_as) do |client|
            client.verbose = false
            client.headers = default_headers.merge(ifmodified.nil? ? {} : { 'If-Modified-Since' => ifmodified })
          end
        end
      elsif defined?(RFuzz)
        client = RFuzz::HttpClient.new(self.server,self.port, :head => default_headers.merge(ifmodified.nil? ? {} : { 'If-Modified-Since' => ifmodified }))
        response = client.get(path)
        yield response.http_body if response.http_status.to_i == 200
      else
        client = Net::HTTP.new(self.server, self.port) 
        client.read_timeout = 500

        req = Net::HTTP::Get.new(path, default_headers.merge(ifmodified.nil? ? {} : { 'If-Modified-Since' => ifmodified }))

        response = client.request(req)
        yield response.body.to_s
      end
    end

    def download_file_if_needed(obj)
      file_path = File.join(STORAGE_PATH, obj.obj.path)
      if File.exists?(file_path)
        check = MD5.md5(File.read(file_path)).hexdigest
        return if check == obj.obj.md5
        puts "[#{Time.now}] File exists, but checksum does not match. Downloading again..."
      end
      @pool.process {
        get_file("/backup/#{obj.id}",nil,file_path) do |data|
          open(file_path,"wb") { |f| f.write(data) } unless data.nil?
        end
        puts "[#{Time.now}] File #{file_path} downloaded."
      }
    end

    def run
      @bits = Models::Bit.find_by_sql [%{ SELECT * FROM parkplace_bits ORDER BY updated_at DESC LIMIT 0,1}]

      get_file("/backup",(@bits.empty? ? nil : @bits[0].updated_at.to_i.to_s)) do |feed|
        new_data = YAML::load(feed)
        new_data.each do |r|
          case r.class.to_s
          when "ParkPlace::Models::User"
            tmp = Models::User.find_by_id(r.attributes['id'])
            if tmp.nil?
              tmp = Models::User.new
              tmp.id = r.attributes['id']
              tmp.created_at = r.attributes['created_at']
            end
            tmp.login = r.attributes['login']
            tmp.secret = r.attributes['secret']
            tmp.password = r.attributes['password']
            tmp.email = r.attributes['email']
            tmp.key = r.attributes['key']
            tmp.superuser = r.attributes['superuser']
            tmp.deleted = r.attributes['deleted']
            tmp.updated_at = r.attributes['updated_at']
            tmp.activated_at = r.attributes['activated_at']
            tmp.skip_before_save = true
          else
            tmp = Models::Bit.find_by_id(r.attributes['id'])
            if tmp.nil?
              tmp = Models::Bit.new()
              tmp.id = r.attributes['id']
              tmp.created_at = r.attributes['created_at']
            end
            tmp.name = r.attributes['name']
            tmp.updated_at = r.attributes['updated_at']
            tmp.type = r.attributes['type']
            if tmp.type == 'Slot' && r.attributes['deleted'].to_i == 0
              file_path = File.join(STORAGE_PATH, r.attributes['obj'].path)
              dir = File.dirname(file_path)
              unless File.exists?(dir)
                puts "[#{Time.now}] Creating directory #{dir}"
                FileUtils.mkdir_p dir
              end
              unless tmp.type != 'Slot' || tmp.obj.nil?
                if r.attributes['obj'].md5 == tmp.obj.md5
                  old_file_path = File.join(STORAGE_PATH, tmp.obj.path)
                  File.move(old_file_path,file_path) if File.exists?(old_file_path) && r.attributes['obj'].path != tmp.obj.path
                else
                  puts "[#{Time.now}] File has changed removing stale files"
                  old_file_path = File.join(STORAGE_PATH, tmp.obj.path)
                  File.unlink(old_file_path) if File.exists?(old_file_path)
                end
              end
            end
            if r.attributes['deleted'].to_i == 1 && !tmp.obj.nil?
              file_path = File.join(STORAGE_PATH, tmp.obj.path)
              if File.exists?(file_path)
                File.unlink(file_path)
                puts "[#{Time.now}] Removed deleted file #{file_path}"
              end
            end
            tmp.obj = r.attributes['obj']
            tmp.lft = r.attributes['lft']
            tmp.meta = r.attributes['meta']
            tmp.owner_id = r.attributes['owner_id']
            tmp.access = r.attributes['access']
            tmp.parent_id = r.attributes['parent_id']
            tmp.rgt = r.attributes['rgt']
            tmp.deleted = r.attributes['deleted']
          end # for case
          class << tmp
            def record_timestamps
              false
            end
          end
          puts "[#{Time.now}] " + (tmp.deleted == 1 ? "Deleted" : (tmp.new_record? ? "Created" : "Updated")) + " #{tmp.class}/#{tmp.id}"
          tmp.save(false)
          class << tmp
            def record_timestamps
              super
            end
          end
          download_file_if_needed(tmp) if tmp.class == "ParkPlace::Models::Slot" && tmp.deleted == 0
        end
      end
      @pool.join
    end
  end
end
