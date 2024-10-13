
# Monitoring

nDPI usually needs only a few packets per flow to get full classification and to get all the required metadata/flow_risks. After that point, nDPI stops processing the flow.
However, in some use cases, it might be useful to allow nDPI to process the *entire* flow (i.e. *all* its packets, without any limits). Some examples:
* to extract all the STUN metadata from a STUN flow
* to extract all the request/replay pairs from a DNS flow
In essence, monitoring allows the application to get the same metadata, multiple times, throughout the entire life of the session.

If monitoring is enabled in a flow:
* structures `ndpi_flow->protos`, `ndpi_flow->http`, `ndpi_flow->stun`,... are populated as usual, usually with the *first* instance of the specific metadata. Nothing changed.
* packet by packet, the new structure `ndpi_flow->monitor` is populated with the metadata of the *current* packet. This information is lost when starting processing the next packet in the same flow; it is the responsibility of the application to get it.

In other words:
* "flow metadata" is saved in `ndpi_flow->protos`, `ndpi_flow->http`, `ndpi_flow->stun`, regardless of the monitoring feature being enabled or not. These fields are always available
* "(curent) packet metadata" is saved in `ndpi_flow->monitor`, only if monitor is enabled.

Monitoring must be explicit enabled with something like: `--cfg=stun,monitoring,1`; to enable/disable monitoring for all protocols you can use `--cfg=any,monitoring,1` but only STUN is supported right now.

Since monitoring processess *all* the flow packets, it might have an impact on performances.

## Implementation notes

* Flows move to monitoring state only after extra-dissections end
* The classification doesn't change for flows in monitoring state
* We probably need to improve TCP reassembler to best handle TCP flows in monitoring state
