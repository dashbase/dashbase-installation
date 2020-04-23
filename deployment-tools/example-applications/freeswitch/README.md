## Kubernetes resource templates

### FreeSWITCH
This [folder](./freeswitch) contains necessary Kubernetes resource files to set up a FreeSWITCH pod with mock data generated.

#### prerequisites
1. StorageClass:
    - dashbase-meta
    - dashbase-data

2. Modify Filebeat hosts manually.
There're two Filebeat hosts we need to change. One is in [filebeat-loader.yml](./freeswitch/filebeat-loader.yml) and the other is in [filebeat.yml](./freeswitch/filebeat.yml);
Changing the `output.elasticsearch.hosts` and `output.elasticsearch.protocol` in the above two files.
```yaml
    output.elasticsearch:
      hosts: "table-freeswitch.staging.svc.cluster.local:7888"
      protocol: "https"
      ssl.verification_mode: "none"
```
3. Edit FreeSWITCH RTP-IP and SIP-IP
Modify [config.yml](./freeswitch/config.yml) to find those two lines, edit them to `freeswitch-internal.<your-namespace>.svc.cluster.local`.
```xml
      <X-PRE-PROCESS cmd="stun-set" data="external_rtp_ip=host:freeswitch-internal.default.svc.cluster.local"/>

      <...>
      <X-PRE-PROCESS cmd="stun-set" data="external_sip_ip=host:freeswitch-internal.default.svc.cluster.local"/>
```

#### How to run
Simplify by run
```shell script
kubectl apply -f kubernetes/resources/templates/freeswitch/
```
or
```shell script
kubectl apply -f kubernetes/resources/templates/freeswitch/ -n <your-namespace>
```
