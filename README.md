This logstash filter tags netflow records according to a list of CIDR to tag mappings.

The list is an external / stand alone text file consisting of lines of the form:

<network>/<mask>,<tag>

The filter can be made to re-load it's in-memory representation of the contents of the
map file without interrupting/restarting the logstash instance by touching a flag file.


