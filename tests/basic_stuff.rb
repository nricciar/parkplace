require 'rubygems'
require 'aws/s3'
require 'benchmark'

bucket_name = 'test_bucket'
test_file = 'test.jpg'

AWS::S3::Base.establish_connection!(
  :access_key_id     => '44CF9590006BF252F707',
  :secret_access_key => 'OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV',
  :server => 'localhost',
  :port => 3002
)

begin
  bucket = AWS::S3::Bucket.find bucket_name
rescue AWS::S3::NoSuchBucket
  bucket = AWS::S3::Bucket.create bucket_name
end

unless AWS::S3::S3Object.exists?(test_file, bucket_name)
  AWS::S3::S3Object.store(test_file, open(test_file), bucket_name, { :access => :public_read })
end

object = AWS::S3::S3Object.find test_file, bucket_name
puts object.metadata.inspect

puts "adding metadata"
object.metadata[:test] = 'hello world'
object.store(:access => :public_read)

grant = AWS::S3::ACL::Grant.new
grant.grantee = AWS::S3::ACL::Grantee.new('uri' => 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers')
grant.permission = 'READ_ACP'
object.acl.grants << grant
object.acl(object.acl)

AWS::S3::S3Object.rename test_file, 'renamed_file.jpg', bucket_name
print "renaming file... "

rn = AWS::S3::S3Object.find 'renamed_file.jpg', bucket_name
puts rn.inspect
puts rn.metadata.inspect

AWS::S3::S3Object.delete 'renamed_file.jpg', bucket_name
print "deleting... "

begin
  AWS::S3::S3Object.find 'renamed_file.jpg', bucket_name
rescue AWS::S3::NoSuchKey
  puts "success"
end
