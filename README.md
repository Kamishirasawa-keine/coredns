# simplifieDNS
<p>一个极简的 DNS 转发/屏蔽器<br/>By GPT6.2Sol</p>
<p>docs are WIP.</p>

## 配置
示例文件见: [Corefile](net/coredns/files/Corefile)

## 内建插件
### [blocklist](plugin/blocklist/blocklist.go)
屏蔽插件, 可接受多个 AdguardHome 格式的屏蔽规则. 支持热重载.<br/>
参数:<br/>
`block_response`: 拒绝时的响应. 可接受的值: `NXDOMAIN`、 `REFUSED`、 `NODATA`、`ZERO`(A: 0.0.0.0 AAAA: [::])

### [splitroute](plugin/splitroute/setup.go)
分流插件.<br/>
参数:<br/>
`mode`: 分流模式. 可接受的值: `local_first`、 `remote_first`. 当其为 `local_first` 时, 当请求命中 `remote.txt` (v2ray 格式)时, 才会转发至 `remote`, 其余转发至 `local`, 反之亦然.<br/>
`fallback`: 回落时限.<br/>
`bootstrap-dns`: 用于解析上游 DNS 域名的 DNS. 仅接受 DoUDP.<br/>
#### splitroute.local
local 上游.<br/>
参数:<br/>
`concurrent`: 并发数. 可接受的值: `(number)`、 `all`<br/>
`pipeline`: (DoT Only)启用 Query Pipelining. <br/>
`via` <br/>
`ecs4/6` <br/>

#### splitroute.remote
见 local.

## LICENSE
[BSD-3-Clause](LICENSE)<br/>
[3rd](THIRD_PARTY.md)
