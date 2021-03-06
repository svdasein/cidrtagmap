# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'ipaddr'
require 'redis'

class MapEntry
	attr_reader :range,:tag
	def initialize(spec = "")
		begin
			parts = spec.split(',',2)
			@range = IPAddr.new(parts[0])
			@tag = parts[1].split(',')
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

	config :mapfilepath, :validate => :string, :default => 'cidrmap.txt'
	config :asnmapfilepath, :validate => :string, :default => 'asn.txt'
	config :ipfieldlist, :optional=> true, :list => true , :validate => :string
	config :redisserver, :optional=> true, :validate => :string
	config :redisnamespace, :optional=> true, :validate => :string
	config :asnfieldlist, :list => true, :validate => :string


	private


	def loadAsnMap
		begin
			asntable = File.readlines(@asnmapfilepath)
			regex = /^ (\d+?)\s+(.+?)\s+/
			@asnmap = Hash[asntable.collect { |line| line.match(regex)}.select {|each| not each.nil?}.collect{|each| [each[1],each[2]] }]
			@logger.info("cidrtagmap: loaded asn map file #{@asnmapfilepath}")
		rescue Exception => e
			@logger.warn("cidrtagmap: error loading asn map file #{@asnmapfilepath}")
			@logger.warn("cidrtagmap: #{e.inspect}")
		end
	end

	def loadLatestMap
		if (not @redisserver) and (File.exist?(@reloadFlagPath) or @cidrMap.nil?)
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
					loadAsnMap
				else
					@logger.debug("cidrtagmap: someone already loaded the map - I'm outta here")
				end
			}
		elsif @redisserver
			if not @redisnamespace
				@logger.warn("cidrtagmap: redisnamespace not defined - using cidrtagmap")
				@redisnamespace = 'cidrtagmap'
			end
			if @redis["#{@redisnamespace}.reloadmap"] == '1' or @cidrMap.nil?
				@mutex.synchronize {
					if @redis["#{@redisnamespace}.reloadmap"] == '1' or @cidrMap.nil?
						@redis["#{@redisnamespace}.reloadmap"] = '0'
						@logger.info("cidrtagmap: refreshing map from redis server at #{@redisserver} using namespace '#{@redisnamespace}'")
						begin
							rawcidrmap = @redis.hgetall("#{@redisnamespace}.cidrmap")
							@cidrMap = rawcidrmap.each.map{ |cidr,tag|
								MapEntry.new("#{cidr},#{tag}")
							}
							@cidrMap = @cidrMap.reject { |item| item.nil? }
							@logger.info("cidrtagmap: loaded #{@cidrMap.inspect}")
						rescue Exception => e
							@logger.error("cidrtagmap: error attempting to load map from redis")
							@logger.error(e.inspect)
						end
						loadAsnMap
					else
						@logger.debug("cidrtagmap: someone already loaded the map - I'm outta here")
					end
				}
			end
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

	def asNameForNumber(as = 0)
		begin
			return @asnmap[as.to_s] || "UNKNOWN"
		rescue
			return "MAPERROR"
		end
	end

	public
	def register
		@mutex = Mutex.new
		if @redisserver
			begin
				@redis = Redis.new(:host=>@redisserver)
				@logger.info("cidrtagmap: connected to redis server at #{@redisserver}")
			rescue Exception => e
				@logger.error("cidrtagmap: failed to connect to redis server at #{@redisserver}")
			end
		else
			@reloadFlagPath = "#{@mapfilepath}.RELOAD"
			@logger.info("cidrtagmap: NOTE: touch #{@reloadFlagPath} to force map reload")
		end
		loadLatestMap
	end

	public
	def filter(event)
		return unless filter?(event)
		loadLatestMap
		if @ipfieldlist
			@ipfieldlist.each { |fieldname|
				@logger.debug("cidrtagmap: looking for ipfield '#{fieldname}'")
				if ipvalue = event.get(fieldname)
					@logger.debug("cidrtagmap: I found ipfield #{fieldname} with value #{ipvalue}")
					mapping = mapForIp(ipvalue)
					if mapping
						@logger.debug("cidrtagmap: I mapped IP address #{ipvalue} to #{mapping.tag} via range #{mapping.range.to_s}")
						event.set("[cidrtagmap]#{fieldname}[tags]",mapping.tag)
						event.set("[cidrtagmap]#{fieldname}[match]",mapping.range.to_s)
						filter_matched(event)
					end
				end
			}
		else
			@logger.warn("cidrtagmap: No IP field list defined - not attempting to translate ip addresses!")
		end
		if @asnfieldlist
			@asnfieldlist.each { |fieldname|
				@logger.debug("cidrtagmap: looking for asnfield '#{fieldname}'")
				if asvalue = event.get(fieldname)
					@logger.debug("cidrtagmap: I found asnfield #{fieldname} with value #{asvalue}")
					asname = asNameForNumber(asvalue)
					if asname
						@logger.debug("cidrtagmap: I mapped as number #{asvalue} to #{asname}")
						event.set("[cidrtagmap]#{fieldname}[asname]",asname)
						filter_matched(event)
					end
				end
			}
		else
			@logger.debug("cidrtagmap: No as field list defined - not attempting to translate asnames!")
		end

	end
end 
