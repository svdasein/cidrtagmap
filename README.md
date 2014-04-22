This logstash filter tags netflow records according to a list of CIDR to tag mappings.

The list is an external / stand alone text file consisting of lines of the form:

```
<network>/<mask>,<tag>
```

The filter can be made to re-load it's in-memory representation of the contents of the
map file without interrupting/restarting the logstash instance by touching a flag file.

When a netflow event matches the CIDR spec, two tags are set:

src_tag = the tag associated with the spec that matched

src_tagMatch = the CIDR spec that matched (as rendered by IPAddr.to_s)


Configuration:

```
filter{
        cidrtagmap {
                mapfilepath => "cidrmap.txt"
        }
}
```

Tell the filter to reload its map

```
touch <mapfilepath>.RELOAD
```

Reloading is thread safe.

