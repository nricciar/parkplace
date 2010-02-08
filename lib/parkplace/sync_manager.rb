require 'parkplace/thread_pool'
require 'rfuzz/session'
require 'open-uri'

module ParkPlace

  class SyncManager

    attr_accessor :server, :secret_key, :username

    def initialize(options = {})
      self.server = options[:server]
      self.secret_key = options[:secret_key].nil? ? 'OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV' : options[:secret_key]
      self.username = options[:username].nil? ? 'admin' : options[:username]
    end

    def auth_header
      "#{self.username}:#{self.secret_key}"
    end

    def http_client
      @bits = Models::Bit.find_by_sql [%{ SELECT * FROM parkplace_bits ORDER BY updated_at DESC LIMIT 0,1}]
      opt = @bits.empty? ? {} : { 'If-Modified-Since' => @bits[0].updated_at.to_i.to_s }
      RFuzz::HttpClient.new(self.server,80, :head => opt.merge({ 'Authorization' => auth_header }))
    end

    def run
      pool = ::ThreadPool.new(10)

      master = self.http_client.get("/backup")
      if master.http_status.to_i == 200
        feed = master.http_body
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
              check = Base64.encode64(MD5.md5(File.read(file_path)).digest).strip
              if check != tmp.obj.md5
                puts "[#{Time.now}] Checksum does not match for #{file_path} re-downloading"
                pool.process {
                  open("http://#{self.server}/backup/#{tmp.id}", { 'Authorization' => auth_header }) do |data|
                    open(file_path,"wb") { |f| f.write(data.read) }
                  end
                  puts "[#{Time.now}] Downloaded #{file_path}"
                }
              else
                puts "[#{Time.now}] Updated file information for #{file_path}"
              end
            else
              pool.process {
                open("http://#{self.server}/backup/#{tmp.id}", { 'Authorization' => auth_header }) do |data|
                  open(file_path,"wb") { |f| f.write(data.read) }
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
