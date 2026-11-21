# pfSense: sending logs to Wazuh

**Status > System Logs > Settings > Remote Logging Options**

| Setting | Value |
|---------|-------|
| Enable Remote Logging | checked |
| Source Address | OPT2 (admin network, 192.168.56.2) |
| IP Protocol | IPv4 |
| Remote log servers | `192.168.56.103:514` (Wazuh manager) |
| Remote Syslog Contents | Everything |

**Services > Suricata > Global Settings**: "Log to System Log" enabled, so Suricata alerts
reach Wazuh through the same syslog stream.

**System > Advanced > Networking**: hardware checksum, TSO and LRO offloading **disabled**
(required for Suricata to inspect packets correctly).

## Why custom Wazuh decoders were needed

pfSense sends BSD syslog (RFC 3164) **without a hostname field**:

```
<134>Nov 20 19:16:46 filterlog[73535]: 103,,,1795136045,em2,match,pass,in,4,...
<141>Nov 20 19:16:45 suricata[12987]: [1:9000002:1] LAB - ... [Priority: 2] {TCP} 10.10.66.100:52492 -> 192.168.1.10:25
```

Wazuh's pre-decoder therefore reads `filterlog[73535]:` / `suricata[12987]:` as the *hostname*,
`program_name` stays empty, and none of the stock pfSense or Suricata decoders match
(`No decoder matched` in `wazuh-logtest`). Switching pfSense to RFC 5424 did not help either.

Solution: decoders that match on the message body itself (`prematch type="pcre2"`, no `^` anchor),
see `configs/wazuh/local_decoder.xml`.
