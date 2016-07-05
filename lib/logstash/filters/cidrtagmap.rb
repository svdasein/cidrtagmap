require "logstash/filters/base"
require "logstash/namespace"
require 'ipaddr'

class MapEntry
	attr_reader :range,:tag
	def initialize(spec = "")
		begin
			parts = spec.split(',')
			@range = IPAddr.new(parts[0])
			@tag = parts[1]
			return self
		rescue
			@logger.warn("cidrtagmap: error parsing map entry #{spec}")
			return nil
		end
	end

	def includesAddress?(ipaddr)
		return @range.include?(ipaddr)
	end
end

class LogStash::Filters::CIDRTagMap < LogStash::Filters::Base

	config_name "cidrtagmap"

	milestone 1

	config :mapfilepath, :validate => :string


	private

	def loadLatestMap
		if File.exist?(@reloadFlagPath) or @cidrMap.nil?
			@logger.debug("cidrtagmap: need to load, getting mutex")
			@mutex.synchronize {
				# Test again now that we have the floor just in case someone else did it already
				# This is because we might have blocked on the mutex when we first encountered the condition
				# We don't wrap the initial test because that'd have the effect of serializing every single
				# netflow event through the test, which defeats the purpose of multiple threads.
				# But we acknowledge that there's room for a race here so test again to be sure.
				if File.exist?(@reloadFlagPath) or @cidrMap.nil?
					if File.exist?(@reloadFlagPath)
						begin
							# This thread wins, clear the flag file.  If someone else is waiting
							# on the mutex they'll see that it's already done when they get in here.
							# We want to do this right away because the longer we wait the more likely
							# it is that other threads are piling up behind the mutex.
							File.delete(@reloadFlagPath)
							@logger.info("cidrtagmap: cleared reload flag")
						rescue
							@logger.warn("cidrtagmap: unable to remove #{@reloadFlagPath} - I'm probably gonna loop in a bad way")
						end
					end
					@logger.info("cidrtagmap: loading map into memory")
					begin
						@mapFile = File.new(@mapfilepath,'r')
						@cidrMap = @mapFile.readlines.map {
							|line|
							MapEntry.new(line.chomp)
						}
						@mapFile.close
						@cidrMap = @cidrMap.reject { |item| item.nil? }
						@logger.info("cidrtagmap: loaded #{@cidrMap.inspect}")
					rescue
						@logger.warn("cidrtagmap: error opening map file #{@mapfilepath}\n")
						@mapFile = nil
					end
				else
					@logger.debug("cidrtagmap: someone already loaded the map - I'm outta here")
				end
			}
		end
	end

	def mapForIp(addrString = "")
		begin
			address = IPAddr.new(addrString.to_s)
			matchIndex = @cidrMap.index{
				|range|
				range.includesAddress?(address)
			}
			if matchIndex
				@logger.debug("cidrtagmap: match for #{address} at #{matchIndex}")
				return @cidrMap[matchIndex]
			else
				return nil
			end
		rescue
			@logger.warn("cidrtagmap: error attempting to map #{addrString}\n")
		end
	end

	public
	def register
		@mutex = Mutex.new
		@reloadFlagPath = "#{@mapfilepath}.RELOAD"
		@logger.info("cidrtagmap: NOTE: touch #{@reloadFlagPath} to force map reload")
		loadLatestMap
	end

	public
	def filter(event)
		return unless filter?(event)
		if event['netflow']
			loadLatestMap
			netflow = event['netflow']
			if netflow["ipv4_src_addr"]
				@logger.debug("cidrtagmap: checking for src #{netflow['ipv4_src_addr']}")
				src_map = mapForIp(netflow["ipv4_src_addr"])
				if src_map
					@logger.debug("cidrtagmap: tagging src #{netflow['ipv4_src_addr']} with #{src_map.tag}")
					netflow["src_tag"] = src_map.tag
					netflow['src_tagMatch'] = src_map.range.to_s
					filter_matched(event)
				end
			end
			if netflow["ipv4_dst_addr"]
				@logger.debug("cidrtagmap: checking for dst #{netflow['ipv4_dst_addr']}")
				dst_map = mapForIp(netflow["ipv4_dst_addr"])
				if dst_map
					@logger.debug("cidrtagmap: tagging dst #{netflow['ipv4_dst_addr']} with #{dst_map.tag}")
					netflow["dst_tag"] = dst_map.tag
					netflow["dst_tagMatch"] = dst_map.range.to_s
					filter_matched(event)
				end
			end
		end
	end
end 
