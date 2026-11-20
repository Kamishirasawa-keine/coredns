# simplifieDNS
<p>一个极简的 DNS 转发/屏蔽器<br/>By GPT6.2Sol</p>

## 配置
示例文件见: [Corefile](net/coredns/files/Corefile)

## 内建插件
### blocklist
屏蔽插件, 可接受多个 AdguardHome 格式的屏蔽规则.<br/>
参数:<br/>
`block_response`: 拒绝时的响应. 可接受的值: `NXDOMAIN`、 `REFUSED`、 `NODATA`、`ZERO`(A: 0.0.0.0 AAAA: [::])

## LICENSE
[BSD-3-Clause](LICENSE)<br/>
[3rd](THIRD_PARTY.md)