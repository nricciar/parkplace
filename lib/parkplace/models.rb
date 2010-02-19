module ParkPlace::Models

  class CreateBits < V 1.0

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

      create_table :parkplace_bits_users do |t|
        t.column :bit_id,  :integer
        t.column :user_id, :integer
        t.column :access,  :integer
      end
    end

    def self.down
      drop_table :parkplace_bits
      drop_table :parkplace_bits_users
      drop_table :parkplace_users
    end

  end

  class CreateUsers < V 1.0

    def self.up
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
    end

    def self.down
      drop_table :parkplace_users
    end

  end

    class CreateTorrents < V 1.0

      def self.up
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
        drop_table :parkplace_torrents
        drop_table :parkplace_torrent_peers
      end

    end

end
