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

    def run
      pool = ::ThreadPool.new(10)
      @bits = Models::Bit.find_by_sql [%{ SELECT * FROM parkplace_bits ORDER BY updated_at DESC LIMIT 0,1}]

      get_file("/backup",(@bits.empty? ? nil : @bits[0].updated_at.to_i.to_s)) do |feed|
        new_data = YAML::load(feed)
        new_data.each do |r|
          exist_check = Models::Bit.find_by_sql [ %{ SELECT * FROM parkplace_bits WHERE id = ?}, r.attributes['id'].to_s ]
          if exist_check.empty?
            tmp = Models::Bit.new()
            tmp.id = r.attributes['id']
          else
            tmp = exist_check.first
          end
          tmp.name = r.attributes['name']
            tmp.updated_at = r.attributes['updated_at']
            tmp.type = r.attributes['type']
            if tmp.type == 'Slot'
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
            tmp.obj = r.attributes['obj']
            tmp.lft = r.attributes['lft']
            tmp.meta = r.attributes['meta']
            tmp.owner_id = r.attributes['owner_id']
            tmp.access = r.attributes['access']
            tmp.parent_id = r.attributes['parent_id']
            tmp.rgt = r.attributes['rgt']
            tmp.created_at = r.attributes['created_at']
            class << tmp
              def record_timestamps
                false
              end
            end
            tmp.save(false)
            class << tmp
              def record_timestamps
                super
              end
            end

          # Files
          if tmp.type == "Slot"
            if File.exists?(file_path)
              check = MD5.md5(File.read(file_path)).hexdigest
              if check != tmp.obj.md5
                puts "[#{Time.now}] Checksum does not match for #{file_path} re-downloading [#{tmp.obj.md5}/#{check}]"
                pool.process {
                  get_file("/backup/#{tmp.id}",nil,file_path) do |data|
                    open(file_path,"wb") { |f| f.write(data.read) } unless data.nil?
                  end
                  puts "[#{Time.now}] Downloaded #{file_path}"
                }
              else
                puts "[#{Time.now}] Updated file information for #{file_path}"
              end
            else
              pool.process {
                get_file("/backup/#{tmp.id}",nil,file_path) do |data|
                  open(file_path,"wb") { |f| f.write(data.read) } unless data.nil?
                end
                puts "[#{Time.now}] Downloaded #{file_path}"
              }
            end
          end
        end
      end




    end
  end
end
