## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
## 2.2.0
 - Altered tag logic to accept and use multiple tags per match.
 - Tag field name has changed - it is now "tags" rather than "tag"
## 2.2.1
 - Updated CHANGELOG

