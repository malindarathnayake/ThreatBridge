# Graylog Integration Guide

This guide explains how to integrate the ThreatBridge with Graylog for automatic threat intelligence enrichment of log data.

## Overview

The ThreatBridge provides HTTP JSON endpoints that can be used as Graylog lookup tables to enrich log messages with threat intelligence data. When a log contains IP addresses or domains that match threat feeds, additional fields will be added indicating the threat status.

## Architecture

```
Graylog Pipeline → Lookup Table → ThreatBridge → Redis
       ↓
Enriched Message with TI Fields
```

## Setup Steps

### 1. Create Data Adapters

Navigate to **System → Lookup Tables → Data Adapters** and create two adapters:

#### TI IP Lookup Adapter

- **Title**: `TI IP Lookup`
- **Name**: `ti_ip_lookup`
- **Type**: `HTTP JSONPath`
- **Configuration**:
  - **URL**: `http://threatbridge:8000/check/ip?ip=${key}`
  - **Single value JSONPath**: `$.found`
  - **Multi value JSONPath**: `$`
  - **HTTP User Agent**: `Graylog TI Lookup`
  - **HTTP Connect timeout**: `5000`
  - **HTTP Read timeout**: `10000`
  - **HTTP Write timeout**: `5000`

#### TI Domain Lookup Adapter

- **Title**: `TI Domain Lookup`  
- **Name**: `ti_domain_lookup`
- **Type**: `HTTP JSONPath`
- **Configuration**:
  - **URL**: `http://threatbridge:8000/check/domain?domain=${key}`
  - **Single value JSONPath**: `$.found`
  - **Multi value JSONPath**: `$`
  - **HTTP User Agent**: `Graylog TI Lookup`
  - **HTTP Connect timeout**: `5000`
  - **HTTP Read timeout**: `10000`
  - **HTTP Write timeout**: `5000`

### 2. Create Caches

Navigate to **System → Lookup Tables → Caches** and create two caches:

#### TI IP Cache

- **Title**: `TI IP Cache`
- **Name**: `ti_ip_cache`
- **Type**: `Guava Cache`
- **Configuration**:
  - **Maximum entries**: `10000`
  - **Expire after access**: `300 seconds` (5 minutes)
  - **Expire after write**: `300 seconds` (5 minutes)

#### TI Domain Cache

- **Title**: `TI Domain Cache`
- **Name**: `ti_domain_cache` 
- **Type**: `Guava Cache`
- **Configuration**:
  - **Maximum entries**: `10000`
  - **Expire after access**: `300 seconds` (5 minutes)
  - **Expire after write**: `300 seconds` (5 minutes)

### 3. Create Lookup Tables

Navigate to **System → Lookup Tables → Lookup Tables** and create two tables:

#### TI IP Lookup Table

- **Title**: `TI IP Lookup Table`
- **Name**: `ti_ip_lookup`
- **Description**: `Threat Intelligence IP Address Lookup`
- **Data Adapter**: `ti_ip_lookup`
- **Cache**: `ti_ip_cache`
- **Default single value**: `false`
- **Default multi value**: `{}`

#### TI Domain Lookup Table

- **Title**: `TI Domain Lookup Table`
- **Name**: `ti_domain_lookup`
- **Description**: `Threat Intelligence Domain Lookup`
- **Data Adapter**: `ti_domain_lookup`
- **Cache**: `ti_domain_cache`
- **Default single value**: `false`
- **Default multi value**: `{}`

### 4. Create Pipeline Rules

Navigate to **System → Pipelines → Manage rules** and create enrichment rules:

#### IP Enrichment Rule

```groovy
rule "TI Enrich Source IP"
when
  has_field("src_ip") OR has_field("srcip") OR has_field("source_ip")
then
  let ip_field = "";
  
  // Check multiple common IP field names
  if (has_field("src_ip")) {
    ip_field = to_string($message.src_ip);
  } else if (has_field("srcip")) {
    ip_field = to_string($message.srcip);
  } else if (has_field("source_ip")) {
    ip_field = to_string($message.source_ip);
  }
  
  // Perform lookup if IP field exists
  if (ip_field != "") {
    let ti_result = lookup("ti_ip_lookup", ip_field);
    
    if (ti_result != null) {
      // Add TI fields if threat found
      if (to_bool(ti_result["found"]) == true) {
        set_field("ti_src_ip_hit", true);
        set_field("ti_src_ip_risk", ti_result["risk"]);
        set_field("ti_src_ip_feeds", ti_result["feeds"]);
        set_field("ti_src_ip_type", ti_result["type"]);
        
        // Set alert flag for high-risk IPs
        if (ti_result["risk"] == "high") {
          set_field("ti_high_risk_src", true);
        }
      } else {
        set_field("ti_src_ip_hit", false);
      }
    }
  }
end
```

#### Destination IP Enrichment Rule

```groovy
rule "TI Enrich Destination IP"
when
  has_field("dst_ip") OR has_field("dstip") OR has_field("dest_ip") OR has_field("destination_ip")
then
  let ip_field = "";
  
  // Check multiple common IP field names
  if (has_field("dst_ip")) {
    ip_field = to_string($message.dst_ip);
  } else if (has_field("dstip")) {
    ip_field = to_string($message.dstip);
  } else if (has_field("dest_ip")) {
    ip_field = to_string($message.dest_ip);
  } else if (has_field("destination_ip")) {
    ip_field = to_string($message.destination_ip);
  }
  
  // Perform lookup if IP field exists
  if (ip_field != "") {
    let ti_result = lookup("ti_ip_lookup", ip_field);
    
    if (ti_result != null) {
      // Add TI fields if threat found
      if (to_bool(ti_result["found"]) == true) {
        set_field("ti_dst_ip_hit", true);
        set_field("ti_dst_ip_risk", ti_result["risk"]);
        set_field("ti_dst_ip_feeds", ti_result["feeds"]);
        set_field("ti_dst_ip_type", ti_result["type"]);
        
        // Set alert flag for high-risk IPs
        if (ti_result["risk"] == "high") {
          set_field("ti_high_risk_dst", true);
        }
      } else {
        set_field("ti_dst_ip_hit", false);
      }
    }
  }
end
```

#### Domain Enrichment Rule

```groovy
rule "TI Enrich Domains"
when
  has_field("domain") OR has_field("hostname") OR has_field("dns_query") OR has_field("url")
then
  let domain_field = "";
  
  // Check multiple common domain field names
  if (has_field("domain")) {
    domain_field = to_string($message.domain);
  } else if (has_field("hostname")) {
    domain_field = to_string($message.hostname);
  } else if (has_field("dns_query")) {
    domain_field = to_string($message.dns_query);
  } else if (has_field("url")) {
    // Extract domain from URL
    let url_parts = split("://", to_string($message.url));
    if (length(url_parts) > 1) {
      let domain_part = split("/", url_parts[1]);
      domain_field = domain_part[0];
    }
  }
  
  // Perform lookup if domain field exists and is valid
  if (domain_field != "" && contains(domain_field, ".")) {
    let ti_result = lookup("ti_domain_lookup", domain_field);
    
    if (ti_result != null) {
      // Add TI fields if threat found
      if (to_bool(ti_result["found"]) == true) {
        set_field("ti_domain_hit", true);
        set_field("ti_domain_risk", ti_result["risk"]);
        set_field("ti_domain_feeds", ti_result["feeds"]);
        set_field("ti_domain_match_type", ti_result["match_type"]);
        set_field("ti_domain_matched_value", ti_result["matched_value"]);
        
        // Set alert flag for high-risk domains
        if (ti_result["risk"] == "high") {
          set_field("ti_high_risk_domain", true);
        }
      } else {
        set_field("ti_domain_hit", false);
      }
    }
  }
end
```

### 5. Create Pipeline

Navigate to **System → Pipelines → Manage pipelines** and create a pipeline:

- **Title**: `Threat Intelligence Enrichment`
- **Description**: `Enrich logs with threat intelligence data`

Add stages:
- **Stage 0**: Add all three TI enrichment rules created above

### 6. Connect Pipeline to Streams

Navigate to **System → Pipelines → Manage pipelines** and connect your TI pipeline to the streams you want to enrich (typically "All messages" or specific log streams).

## Field Reference

After successful enrichment, the following fields will be added to matching log messages:

### IP Address Fields

| Field | Type | Description |
|-------|------|-------------|
| `ti_src_ip_hit` | boolean | Whether source IP matched threat feeds |
| `ti_src_ip_risk` | string | Risk level: high/medium/low |
| `ti_src_ip_feeds` | array | List of matching feed names |
| `ti_src_ip_type` | string | Always "ip" for IP lookups |
| `ti_dst_ip_hit` | boolean | Whether destination IP matched |
| `ti_dst_ip_risk` | string | Risk level for destination IP |
| `ti_dst_ip_feeds` | array | Matching feeds for destination IP |
| `ti_dst_ip_type` | string | Always "ip" for IP lookups |
| `ti_high_risk_src` | boolean | True if source IP is high-risk |
| `ti_high_risk_dst` | boolean | True if destination IP is high-risk |

### Domain Fields

| Field | Type | Description |
|-------|------|-------------|
| `ti_domain_hit` | boolean | Whether domain matched threat feeds |
| `ti_domain_risk` | string | Risk level: high/medium/low |
| `ti_domain_feeds` | array | List of matching feed names |
| `ti_domain_match_type` | string | "exact" or "parent" match |
| `ti_domain_matched_value` | string | Actual matched domain (for parent matches) |
| `ti_high_risk_domain` | boolean | True if domain is high-risk |

## Usage Examples

### Create Alerts

Create alerts for high-risk threats:

**Alert Condition**: `ti_high_risk_src:true OR ti_high_risk_dst:true OR ti_high_risk_domain:true`

### Search Examples

```
# Find all TI hits
ti_src_ip_hit:true OR ti_dst_ip_hit:true OR ti_domain_hit:true

# Find high-risk communications  
ti_high_risk_src:true OR ti_high_risk_dst:true OR ti_high_risk_domain:true

# Find specific feed matches
ti_src_ip_feeds:malwareurl OR ti_domain_feeds:malwareurl

# Find parent domain matches (subdomains)
ti_domain_match_type:parent

# Find communications with known bad IPs
ti_src_ip_hit:true AND ti_src_ip_risk:high
```

### Dashboard Widgets

Create dashboard widgets to monitor TI enrichment:

1. **TI Hit Rate**: Count of messages with `ti_*_hit:true`
2. **Risk Distribution**: Pie chart of `ti_*_risk` values
3. **Top Threat IPs**: Top values of source IPs where `ti_src_ip_hit:true`
4. **Top Threat Domains**: Top values of domains where `ti_domain_hit:true`
5. **Feed Coverage**: Bar chart of `ti_*_feeds` values

## Performance Considerations

### Caching Strategy

- **Cache TTL**: Set to 5-10 minutes for balance between performance and freshness
- **Cache Size**: Size based on unique IP/domain volume (start with 10,000 entries)
- **Hit Rate**: Monitor cache hit rates via Graylog metrics

### Lookup Optimization

```groovy
// Optimize by checking if IP is private before lookup
rule "TI Enrich Source IP (Optimized)"
when
  has_field("src_ip") AND 
  NOT cidr_match("10.0.0.0/8", to_ip($message.src_ip)) AND
  NOT cidr_match("172.16.0.0/12", to_ip($message.src_ip)) AND  
  NOT cidr_match("192.168.0.0/16", to_ip($message.src_ip))
then
  // Perform lookup only for public IPs
  let ti_result = lookup("ti_ip_lookup", to_string($message.src_ip));
  // ... rest of enrichment logic
end
```

### Rate Limiting

The ThreatBridge has built-in rate limiting for manual refreshes, but regular lookups are unlimited. Monitor API performance and consider:

- Scaling ThreatBridge containers horizontally
- Implementing additional caching layers
- Filtering out obviously benign traffic before lookup

## Troubleshooting

### Common Issues

**1. Lookup Table Returns No Results**
```bash
# Test data adapter directly
curl "http://threatbridge:8000/check/ip?ip=1.2.3.4"

# Check Graylog logs for HTTP errors
tail -f /var/log/graylog-server/server.log | grep -i "lookup\|http"
```

**2. Pipeline Rules Not Triggering**
- Verify pipeline is connected to correct streams
- Check field names match your log format
- Test rules with known malicious IPs/domains
- Use debug statements in rules

**3. Performance Issues**
```bash
# Check ThreatBridge performance
curl http://threatbridge:8000/metrics | grep ti_lookup_duration

# Monitor cache hit rates in Graylog
# System → Nodes → [node] → System/Metrics
```

**4. False Positives/Negatives**
- Verify feed data quality via ThreatBridge management UI
- Check domain parent matching behavior
- Review feed sources and risk levels

### Testing Configuration

**Test with known malicious indicators:**

```bash
# Test IP lookup
curl "http://threatbridge:8000/check/ip?ip=192.0.2.1"  

# Test domain lookup  
curl "http://threatbridge:8000/check/domain?domain=example.malware.com"

# Generate test log entries
logger "Test connection from 192.0.2.1 to example.com"
```

**Verify enrichment in Graylog:**
1. Send test log with known bad IP/domain
2. Search for the log message
3. Verify TI fields are added correctly
4. Check field values match API response

## Advanced Configuration

### Custom Risk Thresholds

Modify pipeline rules to implement custom risk logic:

```groovy
// Custom risk scoring
if (ti_result["risk"] == "high") {
  set_field("ti_risk_score", 100);
} else if (ti_result["risk"] == "medium") {
  set_field("ti_risk_score", 50);
} else {
  set_field("ti_risk_score", 10);
}

// Multiple feed correlation
let feed_count = length(ti_result["feeds"]);
if (feed_count > 1) {
  set_field("ti_multi_feed", true);
  set_field("ti_feed_count", feed_count);
}
```

### Integration with SIEM Playbooks

Export TI-enriched logs to external SIEM systems:

```json
{
  "timestamp": "2023-12-03T10:00:00Z",
  "src_ip": "192.0.2.1", 
  "ti_src_ip_hit": true,
  "ti_src_ip_risk": "high",
  "ti_src_ip_feeds": ["malwareurl"],
  "ti_high_risk_src": true
}
```

Use `ti_high_risk_*` fields to trigger automated responses in downstream security tools.

## Maintenance

### Regular Tasks

1. **Monitor Performance**: Check ThreatBridge `/metrics` and Graylog lookup performance
2. **Review Coverage**: Analyze which log sources benefit from TI enrichment
3. **Update Feeds**: Monitor feed freshness via ThreatBridge dashboard
4. **Cache Tuning**: Adjust cache settings based on hit rates and memory usage

### Health Monitoring

Create Graylog alerts for TI system health:

- Alert if ThreatBridge `/health` endpoint fails
- Alert if lookup table error rate exceeds threshold  
- Alert if cache hit rate drops below expected level
- Monitor feed last update timestamps
