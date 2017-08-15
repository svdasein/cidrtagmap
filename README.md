This logstash filter tags events according to a list of CIDR to tag mappings, and optionally maps ASN numbers to names


Example:
--------

```
cidrtagmap {
	#redisserver => '127.0.0.1'
	#redisnamespace => "ereiamjh"
        mapfilepath => "/path/to/ipmap/file"
        asnmapfilepath => "/path/to/asnmap/file"
        ipfieldlist => [
		'host',
		'[netflow][dst_address]',
		'[etc]'
	]
        asfieldlist => [
		'[netflow][dst_as]',
		'[netflow][src_as]
	]
}
```

You must specify a map source. Currently there are two forms of this: file based and redis based.

File based configuration:
-------------------------

* mapfilepath points to an  external / stand alone text file consisting of lines of the form:

```
<network>/<mask>,<tag>
```

The filter can be made to re-load its in-memory representation of the contents of the
ipmap file without interrupting/restarting the logstash instance by touching a flag file.

```
touch <mapfilepath>.RELOAD
```


Redis based configuration:
--------------------------

* redisserver = name or ip address of redis server to connect to. If you define this you should also define:
* redisnamespace = string that will act as a prefix to variables stored in redis


In redis then you should define two items:
* redisnamespace.cidrmap = a hash with cidr => tag kv pairs
* redisnamespace.reloadmap = 1|0 - tell filter to reload map


Other configuration:
--------------------

* ipfieldlist (required) is a list of event fields that will be eligible for mapping.  Everything that matches
will be put in a structure subtending an item called cidrtagmap, so
from the above example a match of the [netflow][dst_address] field would add
cidrtagmap.netflow.dst_address.tag.  A pair to this field will be cidrtagmap.netflow.dst_address.match 
which indicates which rule was matched for the mapping.

* asnmapfilepath (optional) points to a copy of this file: ftp://ftp.arin.net/info/asn.txt 

* asnfieldlist (optional) is a list of fields presumed to contain asn numbers.  Everything that matches
will add e.g. cidrtagmap.netflow.dst_as.asname



