# ncp
Naive capture packet.

## 编译
- Linux Kernel version: 5.4.43-1-MANJARO
- gcc: 10.1.0

注意netfilter和netlink API有变化请使用5.4版本内核编译。

```
make
```

## 测试
- Go version: 1.14.4

```
sudo sh -c "echo 2147483647 > /proc/sys/net/core/rmem_default"
sudo sh -c "echo 2147483647 > /proc/sys/net/core/wmem_default"
sudo sh -c "echo 2147483647 > /proc/sys/net/core/rmem_max"
sudo sh -c "echo 2147483647 > /proc/sys/net/core/wmem_max"
sudo insmod ncp.ko [from="<ip>"] [to="<ip>"] [buf=<bufsize>]
```
- `from`: 可选，只截获指定源IP流量
- `to`：可选，只截获指定目的IP流量
- `buf`：默认 `100`，流量buffer，整数倍时用户态才接收一次。

```
go run app.go [-f <logfile>] [-v] [-b <iobuf>]
```
- `-f`: 指定log文件，默认 `ncp.log`
- `-v`：同时打印log至stdout
- `-b`：iobuffer，默认 `524288`（512K）

目前只截获IPV4的TCP和UDP流量，回环流量只截获一次，其他类型流量可以修改 `check_protocol` 和 `ncp_get_port` 函数轻易扩展。

## 实现
- 内核抓包采用netfilter框架，优点是可以在不同位置截获，本例中在 `NF_INET_PRE_ROUTING` 和 `NF_INET_POST_ROUTING` 即进出口处截取网络包。
- 内核态用户态通信采用netlink机制，相比于内核socket和其他方式可以支持双工通信、内核非阻塞，用户态阻塞，用户进程随时连接断开，组播等特性，对lkm影响较小。
- 用户进程连接后可随时断开（预期或非预期）和重连，预期断开会发送消息告知内核，捕获包后不会触发发送处理，非预期断开内核发送包但无法找到接收者，也不会发生错误。

## 性能测试
使用parallel, tcpdump和sendip进行测试

```
sudo tcpdump -c 1000000 -w 1.pcap -i lo src host 192.168.55.55
printf '100000\n%.0s' {1..10} | sudo parallel -j0 sendip -l {} -d r8 -p ipv4 -is 192.168.55.55 -id 127.0.0.1 -p udp -us r5 -ud r5 127.0.0.1
capinfos 1.pcap
```

文件写入缓存均为512K
(本地模拟，sendip发收包各一次，流量速率和包速率只计算收包，抓包速率计算所有包，因此抓包速率可能大于包速率)

|    组别     | 流量速率(kBps) | 性能损失 | 包速率(kpackets/s) | 抓包速率(kpackets/s) | 抓包速度比（抓包速率/2/包速率） |
| :---------: | :------------: | :------: | :----------------: | :------------------: | :-----------------------------: |
|   原始组    |      5649      |    0%    |        112         |          -           |                -                |
|  无buffer   |      3639      |  35.6%   |         72         |         12.8         |              8.9%               |
|  buffer=10  |      4386      |  22.4%   |         87         |         112          |              64.4%              |
| buffer=100  |      5078      |  10.1%   |        100         |         204          |              102%               |
| buffer=1000 |      5037      |  10.8%   |        100         |          99          |              49.5%              |
