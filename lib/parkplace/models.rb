require 'net/http'

module ParkPlace::Models

    class FileInfo
        attr_accessor :path, :mime_type, :disposition, :size, :md5, :etag
    end

    class User < Base
        has_many :bits, :foreign_key => 'owner_id'
        validates_length_of :login, :within => 3..40
        validates_uniqueness_of :login
        validates_uniqueness_of :key
        validates_presence_of :password
        validates_confirmation_of :password
        attr_accessor :skip_before_save
        has_many :bits_users

        def before_save
          unless self.skip_before_save
            @password_clean = self.password
            self.password = hmac_sha1(self.password, self.secret)
          end
        end
        def after_save
            self.password = @password_clean
        end
        def destroy
            self.deleted = 1
            self.save
        end
    end

    class BitsUser < Base
        belongs_to :bit
        belongs_to :user
    end

    class Bit < Base
        acts_as_nested_set
        serialize :meta
        serialize :obj
        belongs_to :owner, :class_name => 'User', :foreign_key => 'owner_id'
        has_many :bits_users
        has_and_belongs_to_many :users
        has_one :torrent
        validates_length_of :name, :within => 3..255

        def git_init
          begin
            FileUtils.mkdir_p(self.fullpath) unless File.exists?(self.fullpath)
            dir_empty = !Dir.foreach(self.fullpath) {|n| break true unless /\A\.\.?\z/ =~ n}
            g = Git.init(self.fullpath)
            g.config('user.name', self.owner.login)
            g.config('user.email', self.owner.email)
            # if directory is not empty we need to add the files
            # into version control
            unless dir_empty
              g.add('.')
              g.commit_all("Enabling versioning for bucket #{self.name}.")
            end
          rescue Git::GitExecuteError => error_message
            puts "[#{Time.now}] GIT: #{error_message}" if ParkPlace.options.verbose
          end
        end

        def git_repository
          versioning_enabled? ? Git.open(git_repository_path) : nil
        end

        def git_repository_path
          self.obj ? File.join(File.dirname(self.fullpath)) : self.fullpath
        end

        def versioning_enabled?
          defined?(Git) && File.exists?(File.join(git_repository_path,'.git')) ? true : false
        end

        def git_object
          git_repository.log.path(File.basename(self.obj.path)).first if versioning_enabled? && self.obj
        end

        def acl_list
          bit_perms = self.access.to_s(8)
          acls = { :owner => { :id => self.owner.key, :accessnum => 7, :type => "CanonicalUser", :name => self.owner.login, :access => "FULL_ACCESS" },
            :anonymous => { :id => nil, :accessnum => bit_perms[2,1], :access => acl_label(bit_perms[2,1]), 
		:type => "Group", :uri => "http://acs.amazonaws.com/groups/global/AllUsers" },
            :authenticated => { :id => nil, :accessnum => bit_perms[1,1], :access => acl_label(bit_perms[1,1]), 
		:type => "Group", :uri => "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" }
          }.merge(get_acls_for_bin)
          acls.delete_if { |key,value| value[:access] == "NONE" || (key == :authenticated && (!acls[:anonymous].nil? && value[:accessnum] <= acls[:anonymous][:accessnum])) }
        end

        def get_acls_for_bin
          ret = {}
          for a in self.bits_users
            ret[a.user.key] = { :type => "CanonicalUser", :id => a.user.key, :name => a.user.login, :access => acl_label(a.access.to_s(8)[0,1]), 
		:accessnum => a.access.to_s(8)[0,1] }
          end
          ret
        end

        def self.acl_text
          { 0 => "NONE", 1 => "NONE", 2 => "NONE", 3 => "NONE", 4 => "READ", 5 => "READ_ACP", 6 => "WRITE", 7 => "WRITE_ACP" }
        end

        def acl_label(num)
          Bit.acl_text[num.to_i]
        end

        def self.update_last_updated
          tmp = Models::Bit.find_by_sql [%{ SELECT * FROM parkplace_bits ORDER BY updated_at DESC LIMIT 0,1}]
          @@last_time_updated = tmp.empty? ? 0 : tmp.first.updated_at.to_i
        end

        def self.last_time_updated
          @@last_time_updated ||= self.update_last_updated
        end

        def after_save
          @@last_time_updated = self.updated_at.to_i
        end

        def destroy
          # need to keep the record around for slaves
          if self.type == 'Slot' && File.exists?(self.fullpath)
            File.unlink(self.fullpath)
          end
          self.update_attributes({:name => nil, :meta => nil, :obj => nil, :deleted => 1})
          self.save(false)
        end

        def fullpath; File.join(STORAGE_PATH, name) end
        def grant hsh
            if hsh[:access]
                self.access = hsh[:access]
                self.save
            end
        end
        def access_readable
            name, _ = CANNED_ACLS.find { |k, v| v == self.access }
            if name
                name
            else
                [0100, 0010, 0001].map do |i|
                    [[4, 'r'], [2, 'w'], [1, 'x']].map do |k, v|
                        (self.access & (i * k) == 0 ? '-' : v )
                    end
                end.join
            end
        end
        def check_access user, group_perm, user_perm
            !!( if owned_by?(user) or (user and access & group_perm > 0) or (access & user_perm > 0)
                    true
                elsif user
                    acl = users.find(user.id) rescue nil
                    acl and acl.access.to_i & user_perm
                end )
        end
        def owned_by? user
            user and owner_id == user.id
        end

        def acp_writable_by? user
            # if owner
            return true if user && user == owner
            # if can write or better
            return true if user && acl_list[user.key] && acl_list[user.key][:accessnum].to_i == 7
            # if authenticated
            return true if user && acl_list[:authenticated] && acl_list[:authenticated][:accessnum].to_i == 7
            # if anonymous 
            return true if acl_list[:anonymous] && acl_list[:anonymous][:accessnum].to_i == 7
        end

        def acp_readable_by? user
            # if owner
            return true if user && user == owner
            # if can write or better
            return true if user && acl_list[user.key] && acl_list[user.key][:accessnum].to_i >= 5
            # if authenticated
            return true if user && acl_list[:authenticated] && acl_list[:authenticated][:accessnum].to_i >= 5
            # if anonymous 
            return true if acl_list[:anonymous] && acl_list[:anonymous][:accessnum].to_i >= 5
        end

        def readable_by? user
            return true if user && acl_list[user.key] && acl_list[user.key][:accessnum].to_i >= 4
            check_access(user, READABLE_BY_AUTH, READABLE)
        end
        def writable_by? user
            return true if user && acl_list[user.key] && acl_list[user.key][:accessnum].to_i >= 6
            check_access(user, WRITABLE_BY_AUTH, WRITABLE)
        end
    end

    class Bucket < Bit
        validates_format_of :name, :with => /^[-.\w]+$/
        def self.find_root(bucket_name)
            find(:first, :conditions => ['deleted = 0 AND parent_id IS NULL AND name = ?', bucket_name]) or raise NoSuchBucket
        end
        def find_slot(oid)
            Slot.find(:first, :conditions => ['deleted = 0 AND parent_id = ? AND name = ?', self.id, oid]) or raise NoSuchKey
        end
    end

    class Slot < Bit
        def fullpath; File.join(STORAGE_PATH, obj.path) end
        def etag
            if self.obj.respond_to? :etag
                self.obj.etag
            elsif self.obj.respond_to? :md5
                self.obj.md5
            else
               %{"#{MD5.md5(self.obj)}"}
            end
        end
        def check_origin_for_updates!
            readlen = 0
            md5 = MD5.new
            file_changed = false

            begin
              uri = URI.parse(self.meta['origin'])
              http = Net::HTTP.new(uri.host,uri.port)
              timeout(2) do
                http.request_get(uri.request_uri, { 'If-Modified-Since' => self.updated_at.httpdate, 'If-None-Match' => self.obj.etag }) do |response|
                  case response.code.to_i
                  when 404
                    self.destroy
                    raise NoSuchKey
                  when 200
                    File.open(self.fullpath,'r+') do |f|
                      f.pos = 0
                      response.read_body do |segment|
                        md5 << segment
                        readlen += segment.size
                        f.write(segment)
                      end
                      f.truncate(f.pos)
                    end
                    file_changed = self.obj.etag == '"' + md5.hexdigest + '"' ? false : true
                  end
                end
              end
            rescue TimeoutError
              puts "[#{Time.now}] check_origin: Timed Out. Using latest copy" if ParkPlace.options.verbose
            rescue => err
              puts "[#{Time.now}] check_origin: #{err}. Using latest copy" if ParkPlace.options.verbose
            end

            if file_changed
              puts "[#{Time.now}] check_origin: New content from origin.  Updating local copy." if ParkPlace.options.verbose
              info = self.obj
              info.size = readlen
              info.md5 = Base64.encode64(md5.digest).strip
              info.etag = '"' + md5.hexdigest + '"'
              self.obj = info
              self.save()

              if self.versioning_enabled?
                begin
                  self.git_repository.add(File.basename(self.obj.path))
                  tmp = self.git_repository.commit("Added #{self.name} to the Git repository.")
                rescue Git::GitExecuteError => error_message
                  puts "[#{Time.now}] GIT: #{error_message}" if ParkPlace.options.verbose
                end
              end
            end
        end
    end

    class Torrent < Base
        belongs_to :bit
        has_many :torrent_peers
    end

    class TorrentPeer < Base
        belongs_to :torrent
    end

    class SetupParkPlace < V 1.0
        DEFAULT_PASSWORD = 'pass@word1'
        DEFAULT_SECRET = 'OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV'

        def self.up
            create_table :parkplace_bits do |t|
                t.column :id,        :integer,  :null => false
                t.column :owner_id,  :integer
                t.column :parent_id, :integer
                t.column :lft,       :integer
                t.column :rgt,       :integer
                t.column :type,      :string,   :limit => 6
                t.column :name,      :string,   :limit => 255
                t.column :created_at, :timestamp
                t.column :updated_at, :timestamp
                t.column :access,    :integer
                t.column :meta,      :text
                t.column :obj,       :text
                t.column :deleted,   :integer, :default => 0
            end
            add_index :parkplace_bits, :name
            create_table :parkplace_users do |t|
                t.column :id,             :integer,  :null => false
                t.column :login,          :string,   :limit => 40
                t.column :password,       :string,   :limit => 40
                t.column :email,          :string,   :limit => 64
                t.column :key,            :string,   :limit => 64
                t.column :secret,         :string,   :limit => 64
                t.column :created_at,     :datetime
                t.column :updated_at,     :timestamp
                t.column :activated_at,   :datetime
                t.column :superuser,      :integer, :default => 0
                t.column :deleted,        :integer, :default => 0
            end
            User.create :login => "admin", :password => DEFAULT_PASSWORD,
              :email => "admin@parkplace.net", :key => "44CF9590006BF252F707", :secret => DEFAULT_SECRET,
              :activated_at => Time.now, :superuser => 1

            create_table :parkplace_bits_users do |t|
                t.column :bit_id,  :integer
                t.column :user_id, :integer
                t.column :access,  :integer
            end
            create_table :parkplace_torrents do |t|
                t.column :id,        :integer,  :null => false
                t.column :bit_id,    :integer
                t.column :info_hash, :string,   :limit => 40
                t.column :metainfo,  :binary
                t.column :seeders,   :integer,  :null => false, :default => 0
                t.column :leechers,  :integer,  :null => false, :default => 0
                t.column :hits,      :integer,  :null => false, :default => 0
                t.column :total,     :integer,  :null => false, :default => 0
                t.column :updated_at, :timestamp
            end
            create_table :parkplace_torrent_peers do |t|
                t.column :id,         :integer,  :null => false
                t.column :torrent_id, :integer
                t.column :guid,       :string,   :limit => 40
                t.column :ipaddr,     :string
                t.column :port,       :integer
                t.column :uploaded,   :integer,  :null => false, :default => 0
                t.column :downloaded, :integer,  :null => false, :default => 0
                t.column :remaining,  :integer,  :null => false, :default => 0
                t.column :compact,    :integer,  :null => false, :default => 0
                t.column :event,      :integer,  :null => false, :default => 0
                t.column :key,        :string,   :limit => 55
                t.column :created_at, :timestamp
                t.column :updated_at, :timestamp
            end
        end
        def self.down
            drop_table :parkplace_bits
            drop_table :parkplace_users
            drop_table :parkplace_bits_users
            drop_table :parkplace_torrents
            drop_table :parkplace_torrent_peers
        end
    end

end
