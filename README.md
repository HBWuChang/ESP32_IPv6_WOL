### 若使用本项目，你需要准备
- ESP32-S3 SuperMini（或其他ESP32-S3开发板（可能不需要自行编译固件））（或其他ESP32开发板（需自行编译固件））
- 能获取公网ipv6地址、与欲唤醒主机有线连接且有2.4G Wi-Fi的路由器
- 一个域名，且已托管到Cloudflare
- 欲唤醒的主机支持Wake on LAN（WOL）功能且已开启
### 以下步骤基于ESP32-S3 SuperMini开发板
### 烧录步骤（可自行选择其他方法
#### 必须（从release中下载）
1. bootloader.bin 
2. partition-table.bin
3. https_request.bin
#### 可自行选择烧录方式（这里介绍一种
1. 从`https://www.espressif.com.cn/en/support/download/other-tools`下载
`Flash Download Tool`
2. 打开`Flash Download Tool` ChipType选择`ESP32-S3` WorkMode选择`Develop` Load Mode选择`UART`，点击`OK`
3. 勾选上方左侧的三个复选框，并分别选择对应的文件
   - bootloader.bin 选择`bootloader.bin`
   - partition-table.bin 选择`partition-table.bin`
   - https_request.bin 选择`https_request.bin`
4. 设置烧录地址
   - bootloader.bin 输入`0x0`
   - partition-table.bin 输入`0x8000`
   - https_request.bin 输入`0x10000`
5. 下方选择COM为ESP32-S3的串口号，点击`Start`开始烧录（若烧录失败，可尝试按住BOOT键重新插拔USB线
6. 烧录完成请重启ESP32-S3
## 初始设置
### 监视设备
- 通过如`Putty`的串口监视器连接ESP32-S3，选择正确端口号，波特率设置为`115200`
### 使设备联网
- 使用手机或电脑创建名为`ATRI`的2.4GWi-Fi热点，密码为`08280828`
- 若串口监视器显示类似信息：
- - `I (5396) example_common: Connected to example_netif_sta
I (5396) example_common: - IPv4 address: 192.168.2.51,
I (5406) example_common: - IPv6 address: fe80:0000:0000:0000:ceba:97ff:fe1d:2a8c, type: ESP_IP6_ADDR_IS_LINK_LOCAL
I (5416) wifi:<ba-del>idx:0, tid:5
I (5416) ipv4-ipv6-server: Socket created
I (5416) wifi:<ba-add>idx:0 (ifx:0, d4:da:21:73:2e:b2), tid:0, ssn:1, winSize:64
I (5426) ipv4-ipv6-server: Socket bound, port 8080
W (5426) HBWuChang_IPv6_WOL: cloudflare_token is empty, skipping periodic HTTPS request timer.
I (5436) ipv4-ipv6-server: Socket listening
I (5446) main_task: Returned from app_main()`
- 则表示联网成功，ipv4地址为`192.168.2.51`
- 通过开启热点的设备（或同热点下）浏览器访问`http://192.168.2.51:8080`打开配置网页
- 在`Token:`中输入`123456`，点击`Get Configuration`按钮
- 将`WiFi SSID`和`WiFi Password`修改为要唤醒主机相连的2.4G Wi-Fi的名称和密码，点击`Save Configuration`按钮和`Reboot Device`按钮
- 查看串口监视器，观察是否成功连接到指定WIFI并获取新ipv4地址
### 网页配置
- 通过新ipv4地址访问配置网页
- 在`Token`处输入`123456`，点击`Get Configuration`按钮以获取现有配置
- 以下是配置项说明
- - Domain Name: 你绑定到Cloudflare的域名，如`example.com`
- - AAAA Name: 你在Cloudflare上设置的AAAA记录的名称，若欲通过`wol.example.com`访问ESP32，则填写`wol`
- - Cloudflare Token: 你在Cloudflare上生成的API Token（[Cloudflare API Token](https://dash.cloudflare.com/profile/api-tokens) 创建令牌->编辑区域 DNS (使用模板)
- - Server Bind Port: 本网页绑定端口，默认`8080`，可自行修改
- - WiFi SSID: ESP32-S3连接的Wi-Fi名称
- - WiFi Password: ESP32-S3连接的Wi-Fi密码
- 以上设置需通过`Set Configuration`按钮保存，在通过`Reboot Device`按钮重启设备后生效
### 欲唤醒主机
- 需设置好Wake on LAN（WOL）功能（具体设置请参考主板说明书或网上资料
- 需通过网线连接至与ESP32-S3相同的路由器上
## 使用说明
### 唤醒主机
- 通过浏览器访问`http://wol.example.com:8080`（域名和端口号根据实际情况修改）打开网页
- 填入`Token`（默认为`123456`）、MAC Address（如`11:22:33:44:55:66`）、Board Address、Port（一般为`9`）
- 点击`Send WOL`按钮以唤醒主机
### 重置ESP32-S3 SuperMini
- 单击设备上的- BOOT -按钮，设备会恢复到首次烧录状态并重启
### 注意事项
- ESP32在启动时及每`5分钟`会查询一次Cloudflare的AAAA记录，若发现IP地址发生变化，则会自动更新Cloudflare的AAAA记录，点击`try update AAAA record`按钮可立即尝试更新（在未设置Cloudflare Token的情况此功能不可用
- Get Configuration按钮可获取的配置包括WOL的MAC地址、Board Address、Port信息
- 所有按钮均会校验Token和cookie，任一有效会更新并返回cookie，此cookie仅在ESP32非易失性储存一份（即输入一次Token后，在不更换浏览器或清除cookie的情况下，后续操作均可不再输入Token
- `Send WOL`按钮会将当前WOL信息保存到ESP32的非易失性存储中，重启后仍然有效，可通过`Get Configuration`按钮获取