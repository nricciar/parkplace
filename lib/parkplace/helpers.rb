require 'markaby'

module ParkPlace::Views
end

module ParkPlace::Controllers

  @r = []
  class << self
    def r
      @r
    end
    def S3 *u
      r=@r
      c = Class.new {
        meta_def(:urls){u}
        meta_def(:inherited){|x|r<<x}
        class_def(:can_cache) { @request.request_method == 'GET' && @user.nil? ? true : false }
        class_def(:initialize) { |request|
          @request = request
          @env = @request.env
          @input = @request.params

          @meta, @amz = {}, {}
          @env.each do |k,v|
            k = k.downcase.gsub('_', '-')
            @amz[$1] = v.strip if k =~ /^http-x-amz-([-\w]+)$/
            @meta[$1] = v if k =~ /^http-x-amz-meta-([-\w]+)$/
          end

          if @request.cookies["parkplace"]
            checkdata,data = @request.cookies["parkplace"].split("--")
            if OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, ParkPlace::Base.options.secret, data) == checkdata
              @state = Marshal.load(Base64.decode64(data))
            end
          end
          @state ||= Models::Session.new

          auth, key_s, secret_s = *@env['HTTP_AUTHORIZATION'].to_s.match(/^AWS (\w+):(.+)$/)
          date_s = @env['HTTP_X_AMZ_DATE'] || @env['HTTP_DATE']
          if @request.params.has_key?('Signature') and Time.at(request['Expires'].to_i) >= Time.now
            key_s, secret_s, date_s = @request['AWSAccessKeyId'], @request['Signature'], @request['Expires']
          end
          uri = @env['PATH_INFO']
          uri += "?" + @env['QUERY_STRING'] if ParkPlace::RESOURCE_TYPES.include?(@env['QUERY_STRING'])
          canonical = [@env['REQUEST_METHOD'], @env['HTTP_CONTENT_MD5'], @env['HTTP_CONTENT_TYPE'],
            date_s, uri]
          @amz.sort.each do |k, v|
            canonical[-1,0] = "x-amz-#{k}:#{v}"
          end
          @user = ParkPlace::Models::User.find_by_key key_s

          if (@user and secret_s != hmac_sha1(@user.secret, canonical.map{|v|v.to_s.strip} * "\n")) || (@user and @user.deleted == 1)
            raise BadAuthentication
          end
        }
      }
    end
    alias R S3
  end

end

module ParkPlace::UserSession

  def initialize(request)
    super(request)
    if @state.user_id
      @user = ParkPlace::Models::User.find @state.user_id
    end
    return ParkPlace::Base.redirect(Controllers::CLogin) if @user.nil?
  end

end

module ParkPlace::Control

  class Mab < Markaby::Builder
    include ParkPlace::Views
    def tag!(*g,&b)
      h=g[-1]
      [:href,:action,:src].each{|a|(h[a]=self/h[a])rescue 0}
      super
    end
  end

  def errors_for(o); ul.errors { o.errors.each_full { |er| li er } } if !o.nil? && o.errors.any?; end

  def method_missing(*a,&b)
    a.shift if a[0]==:render
    m=Mab.new({},self)
#    s=m.capture{instance_variable_set(:@state, state)}
    s=m.capture{send(*a,&b)}
    s=m.capture{send(:layout){s}} if /^_/!~a[0].to_s and m.respond_to?:layout
    s
  end

end

class Object
  # The hidden singleton lurks behind everyone
  def metaclass; class << self; self; end; end
def meta_eval &blk; metaclass.instance_eval &blk; end

# Adds methods to a metaclass
def meta_def name, &blk
  meta_eval { define_method name, &blk }
end

# Defines an instance method within a class
def class_def name, &blk
  class_eval { define_method name, &blk }
end
end

class Time
  def to_default_s
    strftime("%B %d, %Y at %H:%M")
  end
end

module ParkPlace

  # For controllers which pass back XML directly, this method allows quick assignment
  # of the status code and takes care of generating the XML headers.  Takes a block
  # which receives the Builder::XmlMarkup object.
  def xml status = 200
    xml = Builder::XmlMarkup.new
    xml.instruct! :xml, :version=>"1.0", :encoding=>"UTF-8"
    yield xml
    [status,{'Content-Type' => 'application/xml'},xml.target!]
  end

  # Convenient method for generating a SHA1 digest.
  def hmac_sha1(key, s)
    ipad = [].fill(0x36, 0, 64)
    opad = [].fill(0x5C, 0, 64)
    key = key.unpack("C*")
    if key.length < 64 then
      key += [].fill(0, 0, 64-key.length)
    end

    inner = []
    64.times { |i| inner.push(key[i] ^ ipad[i]) }
    inner += s.unpack("C*")

    outer = []
    64.times { |i| outer.push(key[i] ^ opad[i]) }
    outer = outer.pack("c*")
    outer += Digest::SHA1.digest(inner.pack("c*"))

    return Base64::encode64(Digest::SHA1.digest(outer)).chomp
  end

  def generate_secret
    abc = %{ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz} 
    (1..40).map { abc[rand(abc.size),1] }.join
  end

  def generate_key
    abc = %{ABCDEF0123456789} 
    (1..20).map { abc[rand(abc.size),1] }.join
  end

  POST = %{if(!this.title||confirm(this.title+'?')){var f = document.createElement('form'); this.parentNode.appendChild(f); f.method = 'POST'; f.action = this.href; f.submit();}return false;}

  # Kick out anonymous users.
  def only_authorized; raise ParkPlace::AccessDenied unless @user end
  # Kick out any users which do not have acp read access to a certain resource.
  def only_can_read_acp bit; raise ParkPlace::AccessDenied unless bit.acp_readable_by? @user end
  # Kick out any users which do not have acp write access to a certain resource.
  def only_can_write_acp bit; raise ParkPlace::AccessDenied unless bit.acp_writable_by? @user end
  # Kick out any users which do not have read access to a certain resource.
  def only_can_read bit; raise ParkPlace::AccessDenied unless bit.readable_by? @user end
  # Kick out any users which do not have write access to a certain resource.
  def only_can_write bit; raise ParkPlace::AccessDenied unless bit.writable_by? @user end
  # Kick out any users which do not own a certain resource.
  def only_owner_of bit; raise ParkPlace::AccessDenied unless bit.owned_by? @user end
  # Kick out any non-superusers
  def only_superusers; raise ParkPlace::AccessDenied unless @user.superuser? end

  # Build an ActiveRecord Errors set.
  def error(msg)
    state.errors.add_to_base(msg)
  end
end

module ParkPlace::S3

  def versioning_response_for(bit)
    data = xml do |x|
      x.VersioningConfiguration :xmlns => "http://s3.amazonaws.com/doc/2006-03-01/" do
	x.Versioning bit.versioning_enabled? ? 'Enabled' : 'Suspended'
      end
    end
  end

  def acl_response_for(bit)
    data = xml do |x|
      x.AccessControlPolicy :xmlns => "http://s3.amazonaws.com/doc/2006-03-01/" do
	x.Owner do
	  x.ID bit.owner.key
	  x.DisplayName bit.owner.login
	end
	x.AccessControlList do
	  bit.acl_list.each_pair do |key,acl|
	    x.Grant do
	      x.Grantee "xmlns:xsi" => "http://www.w3.org/2001/XMLSchema-instance", "xsi:type" => acl[:type] do
		if acl[:type] == "CanonicalUser"
		  x.ID acl[:id]
		  x.DisplayName acl[:name]
		else
		  x.URI acl[:uri]
		end
	      end
	      x.Permission acl[:access]
	    end
	  end
	end
      end
    end
  end

  # Parse any ACL requests which have come in.
  def requested_acl(slot=nil)
    if slot && @input.has_key?('versioning')
      only_can_write_acp slot
      @env['rack.input'].rewind
      data = @env['rack.input'].read
      xml_request = REXML::Document.new(data).root

      # check if we are enabling version control
      # FIXME: does not disable version control
      if !slot.versioning_enabled? && xml_request.elements['Status'].text == 'Enabled'
	raise NotImplemented unless defined?(Git)
	slot.git_init
      end
    elsif slot && @input.has_key?('acl')
      only_can_write_acp slot
      @env['rack.input'].rewind
      data = @env['rack.input'].read
      xml_request = REXML::Document.new(data).root
      xml_request.each_element('//Grant') do |element|
	new_perm = element.elements['Permission'].text
	new_access = "#{Models::Bit.acl_text.invert[new_perm]}00".to_i(8)
	grantee = element.elements['Grantee']

	case grantee.attributes["type"]
	when "CanonicalUser"
	  user_check = Models::User.find_by_key(grantee.elements["ID"].text)
	  unless user_check.nil? || slot.owner.id == user_check.id
	    update_user_access(slot,user_check,new_access)
	  end
	when "Group"
	  if grantee.elements['URI'].text =~ /AuthenticatedUsers/
	    slot.access &= ~(slot.access.to_s(8)[1,1].to_i*10)
	    slot.access |= (Models::Bit.acl_text.invert[new_perm]*10).to_s.to_i(8)
	  end
	  if grantee.elements['URI'].text =~ /AllUsers/
	    slot.access &= ~slot.access.to_s(8)[2,1].to_i
	    slot.access |= Models::Bit.acl_text.invert[new_perm].to_s.to_i(8)
	  end
	  slot.save()
	when "AmazonCustomerByEmail"
	  user_check = Models::User.find_by_email(grantee.elements["EmailAddress"].text)
	  unless user_check.nil? || slot.owner.id == user_check.id
	    update_user_access(slot,user_check,new_access)
	  end
	when ""
	else
	  raise NotImplemented
	end
      end
      {}
    else
      {:access => ParkPlace::CANNED_ACLS[@amz['acl']] || ParkPlace::CANNED_ACLS['private']}
    end
  end

  def update_user_access(slot,user,access)
    if slot.acl_list[user.key]
      unless access == slot.acl_list[user.key][:access]
	Models::BitsUser.update_all("access = #{access}", ["bit_id = ? AND user_id = ?", slot.id, user.id ])
      end
    else
      Models::BitsUser.create(:bit_id => slot.id, :user_id => user.id, :access => access)
    end
  end

end

module ParkPlace::Models

  class SchemaInfo < ActiveRecord::Base
    set_table_name "schema_info"
  end

  def self.V(n)
    @final = [n, @final.to_i].max
    m = (@migrations ||= [])
    Class.new(ActiveRecord::Migration) do
      meta_def(:version) { n }
      meta_def(:inherited) { |k| m << k }
    end
  end

  def self.create_schema(opts = {})
    opts[:assume] ||= 0
    opts[:version] ||= @final
    if @migrations
      unless SchemaInfo.table_exists?
        ActiveRecord::Schema.define do
          create_table :schema_info do |t|
            t.column :version, :float
          end
        end
      end

      si = SchemaInfo.find(:first) || SchemaInfo.new(:version => opts[:assume])
      if si.version < opts[:version]
        @migrations.each do |k|
          k.migrate(:up) if si.version < k.version and k.version <= opts[:version]
          k.migrate(:down) if si.version > k.version and k.version > opts[:version]
        end
        si.update_attributes(:version => opts[:version])
      end
    end
  end
end
