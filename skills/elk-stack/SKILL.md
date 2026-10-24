---
name: elk-stack
description: Deploy and manage the ELK Stack (Elasticsearch, Logstash, Kibana) for log aggregation and analysis. 
category: Creative & Media
source: antigravity
tags: [node, api, ai, agent, template, image, security, docker, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/elk-stack
---


# ELK Stack

Centralize and analyze logs with Elasticsearch, Logstash, and Kibana.

## When to Use This Skill

Use this skill when:
- Centralizing logs from multiple sources
- Building log search and analytics platforms
- Creating log-based dashboards and alerts
- Implementing full-text search for logs
- Processing and transforming log data

## Prerequisites

- Docker or server infrastructure
- Sufficient disk space for log storage
- Network access from log sources

## Lab and production boundaries

The Compose file is a local disposable lab with Elasticsearch security disabled; loopback binding does not make it appropriate for shared networks. Production needs verified compatible patched versions, authentication/TLS between components, least-privilege ingestion and reviewed retention. A read-only docker.sock mount still exposes daemon API capabilities; omit it or use a restricted proxy. Redact secrets/PII before ingestion and restrict dashboards/exported logs. Watcher/webhook creation sends recurring external messages and requires the corresponding user instruction. ILM snippets are version-dependent and need a correctly bootstrapped rollover alias/data stream; date-named Logstash indices do not automatically satisfy that contract.

## Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    ports:
      - "127.0.0.1:9200:9200"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config:/usr/share/logstash/config
    ports:
      - "127.0.0.1:5044:5044"
      - "127.0.0.1:5000:5000"
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports:
      - "127.0.0.1:5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.11.0
    user: root
    volumes:
      - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - logstash

volumes:
  elasticsearch-data:
```

## Elasticsearch Configuration

### Index Templates

```json
PUT _index_template/logs-template
{
  "index_patterns": ["logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "logs-policy"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "message": { "type": "text" },
        "level": { "type": "keyword" },
        "service": { "type": "keyword" },
        "host": { "type": "keyword" },
        "trace_id": { "type": "keyword" }
      }
    }
  }
}
```

### Index Lifecycle Management

```json
PUT _ilm/policy/logs-policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "1d"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": { "number_of_shards": 1 },
          "forcemerge": { "max_num_segments": 1 }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "freeze": {}
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

## Logstash Pipeline

### Basic Pipeline

```ruby
# logstash/pipeline/main.conf
input {
  beats {
    port => 5044
  }
  
  tcp {
    port => 5000
    codec => json_lines
  }
}

filter {
  # Parse JSON logs
  if [message] =~ /^\{/ {
    json {
      source => "message"
    }
  }
  
  # Parse timestamp
  date {
    match => ["timestamp", "ISO8601", "yyyy-MM-dd HH:mm:ss"]
    target => "@timestamp"
  }
  
  # Add environment tag
  mutate {
    add_field => { "environment" => "production" }
  }
  
  # Grok pattern for nginx logs
  if [type] == "nginx" {
    grok {
      match => {
        "message" => '%{IPORHOST:client_ip} - %{USER:user} \[%{HTTPDATE:timestamp}\] "%{WORD:method} %{URIPATHPARAM:request} HTTP/%{NUMBER:http_version}" %{NUMBER:status} %{NUMBER:bytes}'
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "logs-%{+YYYY.MM.dd}"
  }
}
```

### Advanced Filtering

```ruby
filter {
  # Parse application logs
  grok {
    match => {
      "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} \[%{DATA:service}\] %{GREEDYDATA:log_message}"
    }
  }
  
  # Extract trace ID from message
  if [log_message] =~ /trace_id=/ {
    grok {
      match => { "log
