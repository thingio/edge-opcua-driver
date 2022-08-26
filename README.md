# edge-opcua-driver

该项目基于 edge-device-driver 开发 OPC-UA 协议设备驱动程序，支持接入 OPCUA 协议设备。

## 使用方法

1. 将 `edge-opcua-driver/etc/resources` 目录下与 `opcua` 相关的产品与设备拷贝至 `edge-device-manager/etc/resources` 的对应目录下；

2. 先启动 edge-device-manager，再启动 edge-opcua-driver；

3. 待驱动初始化完成后，直接通过 MessageBus 进行测试；

4. 测试 HARD-READ 指令：

```shell
# 开启一个终端 订阅设备数据的主题
mosquitto_sub -h 127.0.0.1 -p 1883 -t DATA/v1/# | grep -v STATUS | grep -v state
```

```shell
# 开启另一个终端 模拟 manager 向设备发送读取属性的指令
# 向协议为 opcua，产品 ID 为 led，且设备 ID 为 led 的设备发送 HARD-READ temperature 属性的指令，（123 表示请求 ID，可随意指定）
mosquitto_pub -h 127.0.0.1 -p 1883 -t "DATA/v1/DOWN/opcua/led/led/temperature/HARD-READ/123" -m ""
```

5. 其余指令测试的 TOPIC 格式参考 [物模型操作的 TOPIC 约定](https://github.com/thingio/edge-device-std/blob/main/docs/zh/README.md#%E7%89%A9%E6%A8%A1%E5%9E%8B%E6%93%8D%E4%BD%9C)。

## 调试

### 本地调试

#### GoLand

1. `File` -> `Settings` -> `Go` -> `GOROOT`，设置 Go 版本至少为 1.18；
2. `File` -> `Settings` -> `Go` -> `Go Modules`，勾选 `Enable Go Modules Integration`
   并设置 Environment `GOPROXY=http://goproxy.cn`；
3. 将 `etc/config.yaml.template` 拷贝一份 `etc/config.yaml`，基于 `etc/config.yaml` 文件或环境变量
   （config.yaml 与环境变量使用 [viper](https://github.com/spf13/viper) 进行映射）来决定程序运行时行为；
4. Debug `main.go`（设置 `Working directory` 为 `edge-opcua-driver`）。