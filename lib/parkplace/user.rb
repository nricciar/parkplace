module ParkPlace::Models

  class User < ActiveRecord::Base

    has_many :bits, :foreign_key => 'owner_id'
    has_many :bits_users

    validates_length_of :login, :within => 3..40
    validates_uniqueness_of :login
    validates_uniqueness_of :key
    validates_presence_of :password
    validates_confirmation_of :password

    def destroy
      self.deleted = 1
      self.save
    end

    attr_accessor :skip_before_save

    protected
    def before_save
      unless self.skip_before_save
        @password_clean = self.password
        self.password = hmac_sha1(self.password, self.secret)
      end
    end

    def after_save
      self.password = @password_clean
    end

  end

  class CreateUsers < ActiveRecord::Migration

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
      User.create :login => "admin", :password => DEFAULT_PASSWORD,
        :email => "admin@parkplace.net", :key => "44CF9590006BF252F707", :secret => DEFAULT_SECRET,
        :activated_at => Time.now, :superuser => 1
    end

    def self.down
      drop_table :parkplace_users
    end

  end

end
