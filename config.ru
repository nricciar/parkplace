$PARKPLACE_ACCESSORIES = true
require 'parkplace'

ParkPlace.config(ParkPlace.options)
use Rack::Head
use Rack::ShowExceptions
use Rack::CommonLogger

map "/" do
  run ParkPlace
end
map "/control/s/" do
  run Rack::File.new(ParkPlace::STATIC_PATH)
end

if $PARKPLACE_ACCESSORIES
  map "/backup" do
    run ParkPlace::BackupManager.new
  end
end
