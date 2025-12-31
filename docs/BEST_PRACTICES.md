# UniFi MCP Server - Best Practices

Recommendations for optimal use of the UniFi MCP Server.

## Table of Contents

- [Prompting Best Practices](#prompting-best-practices)
- [Security Best Practices](#security-best-practices)
- [Performance Optimization](#performance-optimization)
- [Data Management](#data-management)
- [Integration Best Practices](#integration-best-practices)
- [Troubleshooting Best Practices](#troubleshooting-best-practices)

---

## Prompting Best Practices

### ✅ DO: Be Specific

**Good:**
```
"Show me the health status of the default site and list any offline devices"
```

**Why:** Claude can focus on exactly what you need and provide relevant information.

### ❌ DON'T: Be Vague

**Bad:**
```
"Show me network stuff"
```

**Why:** Unclear what information is needed, resulting in incomplete responses.

---

### ✅ DO: Include Context

**Good:**
```
"I'm troubleshooting slow WiFi. Show me WiFi network configuration, 
connected clients, and AP statistics"
```

**Why:** Claude understands the problem and gathers relevant diagnostic data.

### ❌ DON'T: Lack Context

**Bad:**
```
"Get WiFi info"
```

**Why:** Too generic, might get irrelevant data.

---

### ✅ DO: Combine Related Requests

**Good:**
```
"List all devices, check their status, and identify any that are offline"
```

**Why:** More efficient than separate requests and provides complete context.

### ❌ DON'T: Make Redundant Requests

**Bad:**
```
First: "List devices"
Then: "Check device status"
Then: "Find offline devices"
```

**Why:** Claude can do this in one request more efficiently.

---

### ✅ DO: Ask for Analysis, Not Just Data

**Good:**
```
"Analyze our network traffic and recommend optimizations"
```

**Why:** Claude provides actionable insights, not just raw data.

### ❌ DON'T: Just Ask for Raw Output

**Bad:**
```
"Show me client stats"
```

**Why:** Raw data is less useful without analysis.

---

### ✅ DO: Use Pagination for Large Results

**Good:**
```
"Get the first 50 connected clients and show me their signal strength"
```

**Why:** Prevents overwhelming response and focuses on important data.

### ❌ DON'T: Request Huge Datasets

**Bad:**
```
"Show me all clients and all their statistics"
```

**Why:** May timeout or return unwieldy results.

---

### ✅ DO: Ask for Reports

**Good:**
```
"Generate a network health report for this week"
```

**Why:** Claude structures complex information into useful format.

### ❌ DON'T: Ask for Raw Data Multiple Times

**Bad:**
```
"Get site health, list devices, get clients, get stats, analyze"
```

**Why:** Better as a single request for a comprehensive report.

---

## Security Best Practices

### 🔐 API Key Management

**DO:**
- ✅ Store API key in `.env` file (not version control)
- ✅ Use strong, randomly generated keys
- ✅ Rotate keys periodically (quarterly recommended)
- ✅ Use separate keys for different environments (dev/prod)
- ✅ Grant minimum required permissions per key

**DON'T:**
- ❌ Commit `.env` to version control
- ❌ Share API keys in chat or email
- ❌ Use the same key for multiple systems
- ❌ Use weak or memorable keys
- ❌ Leave old keys active after rotation

---

### 🔒 Network Security

**DO:**
- ✅ Run on secure, authenticated networks
- ✅ Use VPN for remote access
- ✅ Monitor API access logs
- ✅ Implement firewall rules
- ✅ Use HTTPS/TLS for all connections

**DON'T:**
- ❌ Expose MCP server to public internet
- ❌ Run without authentication
- ❌ Disable SSL verification in production
- ❌ Allow unencrypted connections
- ❌ Share controller access widely

---

### 🛡️ Access Control

**DO:**
- ✅ Use API keys with minimal required permissions
- ✅ Create separate keys for different tools/users
- ✅ Audit API key usage regularly
- ✅ Revoke unused keys
- ✅ Document key purposes

**DON'T:**
- ❌ Use admin keys for read-only operations
- ❌ Share keys across multiple users
- ❌ Use same key indefinitely
- ❌ Grant unnecessary permissions
- ❌ Ignore access logs

---

## Performance Optimization

### ⚡ Optimize Queries

**DO:**
- ✅ Use filters and parameters to narrow results
- ✅ Request only needed data
- ✅ Batch related queries together
- ✅ Cache frequently accessed data
- ✅ Use pagination for large datasets

**DON'T:**
- ❌ Request everything and filter client-side
- ❌ Make separate requests for related data
- ❌ Repeatedly query static data
- ❌ Request all results at once
- ❌ Ignore rate limiting

---

### 🚀 Reduce Latency

**DO:**
- ✅ Place MCP server on same network as controller
- ✅ Use direct IP addresses when possible
- ✅ Minimize request frequency
- ✅ Use connection pooling (built-in)
- ✅ Monitor and optimize slow queries

**DON'T:**
- ❌ Run MCP server on slow network
- ❌ Use DNS resolution for every request
- ❌ Hammer API with rapid requests
- ❌ Create new connections repeatedly
- ❌ Ignore slow response patterns

---

### 💾 Handle Large Responses

**DO:**
- ✅ Use pagination (limit/offset)
- ✅ Filter at the API level
- ✅ Request specific fields only
- ✅ Compress responses if needed
- ✅ Stream large results

**DON'T:**
- ❌ Request all records at once
- ❌ Manually filter massive datasets
- ❌ Request every available field
- ❌ Store redundant copies
- ❌ Block on large transfers

---

### 🔄 Rate Limiting

**DO:**
- ✅ Respect API rate limits
- ✅ Implement exponential backoff
- ✅ Space out queries appropriately
- ✅ Monitor rate limit headers
- ✅ Plan usage to stay below limits

**DON'T:**
- ❌ Hammer API rapidly
- ❌ Make dozens of parallel requests
- ❌ Retry immediately on failure
- ❌ Exceed documented limits
- ❌ Ignore rate limit responses

---

## Data Management

### 📊 Data Freshness

**DO:**
- ✅ Understand data may be slightly stale
- ✅ Cache results appropriately (5-10 minutes)
- ✅ Query as needed, not continuously
- ✅ Account for network latency
- ✅ Use real-time alerts for critical data

**DON'T:**
- ❌ Expect real-time data
- ❌ Query every second
- ❌ Trust cached data > 30 minutes old
- ❌ Ignore latency in results
- ❌ Use API data for microsecond timing

---

### 🗂️ Organization

**DO:**
- ✅ Document which data you use regularly
- ✅ Create useful aliases/shortcuts
- ✅ Organize data by site/department
- ✅ Keep historical records
- ✅ Automate data collection

**DON'T:**
- ❌ Mix data from different sources
- ❌ Lose track of data origins
- ❌ Store sensitive data unnecessarily
- ❌ Keep indefinite historical data
- ❌ Manual data collection

---

### 🔍 Accuracy

**DO:**
- ✅ Verify unexpected results
- ✅ Cross-check data from multiple sources
- ✅ Understand data limitations
- ✅ Document assumptions
- ✅ Report discrepancies

**DON'T:**
- ❌ Trust single data point
- ❌ Act on anomalies without verification
- ❌ Ignore data quality warnings
- ❌ Use data outside scope
- ❌ Assume perfect accuracy

---

## Integration Best Practices

### 🔗 Claude Integration

**DO:**
- ✅ Keep server running in background
- ✅ Verify tools load on Claude startup
- ✅ Test periodically
- ✅ Monitor for errors
- ✅ Update credentials in one place

**DON'T:**
- ❌ Start/stop server frequently
- ❌ Ignore tool availability warnings
- ❌ Use without testing first
- ❌ Leave errors unchecked
- ❌ Store credentials in multiple places

---

### 🔧 Workflow Integration

**DO:**
- ✅ Create standardized processes
- ✅ Document common queries
- ✅ Reuse proven prompts
- ✅ Build on successful patterns
- ✅ Share knowledge with team

**DON'T:**
- ❌ Use ad-hoc queries
- ❌ Reinvent solutions repeatedly
- ❌ Use different approaches for same task
- ❌ Keep knowledge isolated
- ❌ Change working processes frequently

---

### 🤖 Automation

**DO:**
- ✅ Automate repetitive checks
- ✅ Schedule regular reports
- ✅ Create alert workflows
- ✅ Use cron/scheduled tasks
- ✅ Monitor automation success

**DON'T:**
- ❌ Manually run same query daily
- ❌ Generate reports manually
- ❌ Ignore patterns in alerts
- ❌ Run checks randomly
- ❌ Assume automation works without verification

---

## Troubleshooting Best Practices

### 🔍 Problem Diagnosis

**DO:**
- ✅ Enable debug logging first
- ✅ Test basic connectivity
- ✅ Check configuration
- ✅ Review recent changes
- ✅ Verify prerequisites

**DON'T:**
- ❌ Jump to complex solutions
- ❌ Skip basic checks
- ❌ Ignore error messages
- ❌ Assume knowledge of cause
- ❌ Skip verification steps

---

### 🛠️ Debugging

**DO:**
- ✅ Use `LOG_LEVEL=debug`
- ✅ Test with curl first
- ✅ Check each layer separately
- ✅ Document what you try
- ✅ Keep debug logs for analysis

**DON'T:**
- ❌ Debug blindly
- ❌ Skip curl tests
- ❌ Test everything at once
- ❌ Forget what you tried
- ❌ Delete debug information

---

### 📝 Documentation

**DO:**
- ✅ Document issues and solutions
- ✅ Keep troubleshooting logs
- ✅ Update runbooks
- ✅ Share solutions with team
- ✅ Create FAQ for common issues

**DON'T:**
- ❌ Forget how you fixed it
- ❌ Solve same problem twice
- ❌ Keep knowledge isolated
- ❌ Ignore patterns
- ❌ Let documentation decay

---

## Maintenance Best Practices

### 🔄 Updates

**DO:**
- ✅ Stay current with UniFi updates
- ✅ Update Go periodically
- ✅ Monitor for security updates
- ✅ Test updates before production
- ✅ Maintain backups

**DON'T:**
- ❌ Ignore available updates
- ❌ Use outdated Go version
- ❌ Delay security patches
- ❌ Update production immediately
- ❌ Skip backup before update

---

### 📋 Monitoring

**DO:**
- ✅ Monitor server health
- ✅ Check logs regularly
- ✅ Track error rates
- ✅ Monitor performance
- ✅ Alert on critical issues

**DON'T:**
- ❌ "Set and forget"
- ❌ Ignore logs
- ❌ Allow errors to accumulate
- ❌ Not know if system is healthy
- ❌ React only to failures

---

### 🧹 Maintenance

**DO:**
- ✅ Clear old logs periodically
- ✅ Archive historical data
- ✅ Rebuild cache when needed
- ✅ Update configuration
- ✅ Review and optimize regularly

**DON'T:**
- ❌ Let logs grow unbounded
- ❌ Keep unnecessary old data
- ❌ Allow cache to become stale
- ❌ Never update configuration
- ❌ Run without optimization

---

## Documentation Best Practices

### 📚 Keep Documentation Updated

**DO:**
- ✅ Update docs with changes
- ✅ Document custom configurations
- ✅ Keep examples current
- ✅ Note limitations and gotchas
- ✅ Version documentation

**DON'T:**
- ❌ Let docs become stale
- ❌ Assume documentation is obvious
- ❌ Document only happy path
- ❌ Hide complexity
- ❌ Forget edge cases

---

## Team Best Practices

### 👥 Knowledge Sharing

**DO:**
- ✅ Share successful prompts
- ✅ Document team standards
- ✅ Conduct knowledge sharing sessions
- ✅ Create team playbooks
- ✅ Mentor junior team members

**DON'T:**
- ❌ Keep knowledge isolated
- ❌ Use undocumented approaches
- ❌ Reinvent solutions
- ❌ Ignore team standards
- ❌ Gatekeep expertise

---

### 🎯 Standardization

**DO:**
- ✅ Use consistent naming
- ✅ Follow team standards
- ✅ Document conventions
- ✅ Automate standard checks
- ✅ Share templates

**DON'T:**
- ❌ Use inconsistent approaches
- ❌ Ignore team standards
- ❌ Create individual systems
- ❌ Manual repetitive work
- ❌ Prevent knowledge transfer

---

## Quick Reference Checklist

### Daily
- [ ] Check network health
- [ ] Review for offline devices
- [ ] Monitor for errors
- [ ] Check storage capacity

### Weekly
- [ ] Generate status report
- [ ] Review security rules
- [ ] Check device updates
- [ ] Analyze trends

### Monthly
- [ ] Complete security audit
- [ ] Review and optimize WiFi
- [ ] Analyze capacity
- [ ] Plan improvements

### Quarterly
- [ ] Rotate API keys
- [ ] Major firmware updates
- [ ] Infrastructure review
- [ ] Disaster recovery test

### Annually
- [ ] Complete infrastructure audit
- [ ] Hardware refresh planning
- [ ] Security assessment
- [ ] Capacity planning

---

These best practices will help you get the most value from the UniFi MCP Server while maintaining security, performance, and reliability!
