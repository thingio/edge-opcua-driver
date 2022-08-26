package driver

import (
	"context"
	"fmt"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/thingio/edge-device-std/errors"
	"github.com/thingio/edge-device-std/logger"
	"github.com/thingio/edge-device-std/models"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	NodePathSep    = "/"       // OPCUA 设备节点路径的分隔符 e.g. Objects/Device1
	NodePathPrefix = "Objects" // OPCUA 设备节点路径的前缀, 所有设备节点Path必须具有该前缀

	OPCUAExtendDisplayName            = "display_name" // 对应Node的DisplayName
	OPCUADeviceReadInterval           = "interval"     // 设备层次的数据采集间隔
	OPCUADeviceAuto                   = "auto"         // 是否自动获取设备属性
	OPCUADeviceWriteBack              = "write_back"   // 是否将获取到的设备属性写回产品
	OPCUADeviceEndpoint               = "endpoint"     // 设备OPCUA Server地址
	OPCUADeviceSecurityPolicy         = "sc_policy"    // 安全策略
	OPCUADeviceSecurityMode           = "sc_mode"      // 安全模式
	OPCUADeviceSecurityUserName       = "username"     // 用户名
	OPCUADeviceSecurityPassword       = "password"     // 密码
	OPCUADeviceSecurityCertFile       = "cert_file"    // 数字证书文件路径
	OPCUADeviceSecurityKeyFile        = "key_file"     // 秘钥证书文件路径
	OPCUADeviceSecurityNodePath       = "node_path"    // 设备节点所在绝对路径
	OPCUAEndPointPrefix               = "opc.tcp://"
	OPCUASecurityPolicyNone           = "None"
	OPCUASecurityPolicyBasic128Rsa15  = "Basic128Rsa15"
	OPCUASecurityPolicyBasic256       = "Basic256"
	OPCUASecurityPolicyBasic256Sha256 = "Basic256Sha256"
	OPCUASecurityModeNone             = "None"
	OPCUASecurityModeSign             = "Sign"
	OPCUASecurityModeSignAndEncrypt   = "SignAndEncrypt"

	RegularMode          = "regular" // using interval : 5s, 1m, 0.5h
	DriverConnectTimeout = 3 * time.Second

	EventQueueSize int = 100

	EventFunc ProductFuncType = "events"
)

type (
	Method           = func(ins map[string]*models.DeviceData) (outs map[string]*models.DeviceData, err error)
	MethodName       = string
	MethodInputName  = string
	MethodOutputName = string

	ProductFuncID   = string
	ProductPropID   = ProductFuncID
	ProductFuncType = string // 产品功能的类型

	DeviceOperation = string // 设备操作的类型
)

var (
	AvailableOPCUASecurityPolicies = map[string]struct{}{
		OPCUASecurityPolicyNone:           {},
		OPCUASecurityPolicyBasic128Rsa15:  {},
		OPCUASecurityPolicyBasic256:       {},
		OPCUASecurityPolicyBasic256Sha256: {},
	}
	AvailableOPCUASecurityModes = map[string]struct{}{
		OPCUASecurityModeNone:           {},
		OPCUASecurityModeSign:           {},
		OPCUASecurityModeSignAndEncrypt: {},
	}

	displayname2Nodeid = map[string]*ua.NodeID{} //存储节点name到nodeId的映射
)

// opcuaEvtHandler 为用于处理opcua server产生的事件的回调函数
type opcuaEvtHandler = func(values []*ua.Variant)

type opcuaDriver struct {
	*opcuaDeviceConf                            // 设备的配置
	pid              string                     // 设备所属产品的ID
	dvcID            string                     // 设备ID
	cli              *opcua.Client              // 用于同opcua server进行交互的client
	readReq          *ua.ReadRequest            // 用于请求设备的所有属性的请求
	root             *TreeNode                  // 设备对应的OPCUA根节点
	connected        bool                       // 标识opcua client是否已连接
	evtHandles       map[uint32]opcuaEvtHandler // evt handle -> evt id
	subscription     *opcua.Subscription
	once             sync.Once // 用于单例启动自动重连协程的对象
	//sub     *opcua.Subscription // 用于接受Server端消息通知的订阅
}

type opcuaDeviceConf struct {
	AuthMode     string        // 验证方式 Auth mode:
	ScMode       string        // 安全模式 Security mode: None, Sign, SignAndEncrypt. Default: auto
	ScPolicy     string        // 安全策略 Security policy: None, Basic128Rsa15, Basic256, Basic256Sha256. Default: auto
	Endpoint     string        // 设备OPCUA Server地址,e.g. opc.tcp://172.16.251.121:4840/freeopcua/server
	UserName     string        // 用户名
	Password     string        // 密码
	CertFile     string        // 数字证书 cert.pem. Required for security mode/policy != None
	KeyFile      string        // 秘钥证书 private key.pem. Required for security mode/policy != None
	NodePath     string        // 设备节点路径  e.g. Objects/demo_led
	ReadInterval time.Duration // 设备数据采集间隔
	AutoConf     bool          // 自动获取设备配置
	WriteBack    bool          // 将自动获取到的
}

type opcuaTwin struct {
	*opcuaDriver
	product *models.Product
	device  *models.Device

	properties map[models.ProductPropertyID]*models.ProductProperty // for property's reading and writing
	events     map[models.ProductEventID]*models.ProductEvent       // for event's subscribing
	methods    map[models.ProductMethodID]*models.ProductMethod     // for method's calling

	lg     *logger.Logger
	ctx    context.Context    // 标识当前driver生命周期的上下文
	cancel context.CancelFunc // 用于关闭当前driver生命周期的方法句柄
}

func NewOPCUADriver(device *models.Device) *opcuaDriver {
	conf, err := parseOpcuaDeviceConf(device)
	if err != nil {
		return nil
	}
	return &opcuaDriver{
		opcuaDeviceConf: conf,
		pid:             "",
		dvcID:           "",
		cli:             nil,
		readReq:         nil,
		root:            nil,
		connected:       false,
		evtHandles:      make(map[uint32]opcuaEvtHandler),
		subscription:    nil,
		once:            sync.Once{},
	}
}

func parseOpcuaDeviceConf(device *models.Device) (*opcuaDeviceConf, error) {
	dc := &opcuaDeviceConf{}
	p, pe := device.DeviceProps[OPCUADeviceSecurityPolicy]
	m, me := device.DeviceProps[OPCUADeviceSecurityMode]
	needCert := pe && me && p != OPCUASecurityPolicyNone && m != OPCUASecurityModeNone
	for k, v := range device.DeviceProps {
		switch k {
		case OPCUADeviceEndpoint:
			if !strings.HasPrefix(v, OPCUAEndPointPrefix) {
				return dc, errors.NewCommonEdgeError(errors.Configuration, fmt.Sprintf("endpoint of opcua device mast has prefix:%s", OPCUAEndPointPrefix), nil)
			}
			dc.Endpoint = v
		case OPCUADeviceSecurityPolicy:
			if _, ok := AvailableOPCUASecurityPolicies[v]; !ok {
				return dc, errors.NewCommonEdgeError(errors.Configuration, fmt.Sprintf("security policy of opcua device not support %s", v), nil)
			}
			dc.ScPolicy = v
		case OPCUADeviceSecurityMode:
			if _, ok := AvailableOPCUASecurityModes[v]; !ok {
				return dc, errors.NewCommonEdgeError(errors.Configuration, fmt.Sprintf("security mode of opcua device not support %s", v), nil)
			}
			dc.ScMode = v
		case OPCUADeviceSecurityUserName:
			dc.UserName = v
		case OPCUADeviceSecurityPassword:
			dc.Password = v
		case OPCUADeviceSecurityCertFile:
			if needCert {
				dc.CertFile = v
			}
		case OPCUADeviceSecurityKeyFile:
			if needCert {
				dc.KeyFile = v
			}
		case OPCUADeviceSecurityNodePath:
			dc.NodePath = v
		case OPCUADeviceReadInterval:
			d, err := time.ParseDuration(v)
			if err != nil {
				return dc, errors.NewCommonEdgeError(errors.Configuration, fmt.Sprintf("invalid read interval %s of opcua device", v), nil)
			}
			dc.ReadInterval = d
		case OPCUADeviceAuto:
			dc.AutoConf, _ = strconv.ParseBool(v)
		case OPCUADeviceWriteBack:
			dc.WriteBack, _ = strconv.ParseBool(v)
		default:
			return dc, errors.NewCommonEdgeError(errors.Configuration, fmt.Sprintf("unsupported opcua device prop %s", k), nil)
		}
	}
	return dc, nil
}

func NewOpcuaTwin(product *models.Product, device *models.Device) (models.DeviceTwin, error) {
	if product == nil {
		return nil, errors.NewCommonEdgeError(errors.DeviceTwin, "Product is nil", nil)
	}
	if device == nil {
		return nil, errors.NewCommonEdgeError(errors.DeviceTwin, "Device is nil", nil)
	}
	opcDriver := NewOPCUADriver(device)
	if opcDriver == nil {
		return nil, errors.NewCommonEdgeError(errors.DeviceTwin, "opcuaDriver is nil", nil)
	}
	twin := &opcuaTwin{
		opcuaDriver: opcDriver,
		product:     product,
		device:      device,
		properties:  make(map[models.ProductPropertyID]*models.ProductProperty),
		events:      make(map[models.ProductEventID]*models.ProductEvent),
		methods:     make(map[models.ProductMethodID]*models.ProductMethod),
	}
	return twin, nil
}

func (o *opcuaTwin) Initialize(lg *logger.Logger) error {
	o.lg = lg
	o.opcuaDriver.pid = o.product.ID
	o.opcuaDriver.dvcID = o.device.ID

	o.properties = make(map[models.ProductPropertyID]*models.ProductProperty)
	for _, property := range o.product.Properties {
		o.properties[property.Id] = property
	}
	for _, event := range o.product.Events {
		o.events[event.Id] = event
	}
	o.lg.Info("success to initialize the opcua device twin")
	return nil
}

func (o *opcuaTwin) Start(ctx context.Context) error {
	o.ctx, o.cancel = context.WithCancel(ctx)

	// 启动前清理残留对象
	if o.cli != nil {
		_ = o.cli.Close()
	}
	if o.cancel != nil {
		o.cancel()
	}

	// 通过 cancel 与 context 控制定时读属性的协程
	o.ctx, o.cancel = context.WithCancel(context.Background())
	if err := o.initClient(); err != nil {
		o.lg.Errorf("failed to initialize opcua client")
		return err
	}

	// find the opcua node corresponding to device
	treeRoot, err := o.FindNodeByPath(o.NodePath)
	if err != nil {
		o.lg.Errorf("failed to find node by path '%s'", o.NodePath)
		return err
	}

	// build node tree
	if err := treeRoot.Build(); err != nil {
		o.lg.Errorf("failed to build the tree of node '%s'", treeRoot.id.String())
		return err
	}
	o.root = treeRoot

	// 初始化当前节点及其所有子节点的 DisplayName -> NodeID 的映射
	displayname2Nodeid = o.root.DisplayNames()

	// init read req
	o.initReadReq()

	// init subscription
	if err := o.initEvtSubscription(); err != nil {
		o.lg.Errorf("failed to init event subscription")
		return err
	}

	// 设置当前连接状态
	o.connected = true

	return nil
}

func (o *opcuaTwin) Stop(force bool) error {
	if o.cli != nil {
		if err := o.cli.Close(); err != nil {
			o.lg.Info("error while closing opcuaTwin driver")
		}
	}
	if o.cancel != nil {
		o.cancel()
	}
	return nil
}

func (o *opcuaTwin) HealthCheck() (*models.DeviceStatus, error) {
	hbTicker := time.NewTicker(time.Second * 5)
	select {
	case <-hbTicker.C:
		if o.connected != false {
			err := o.ping()
			// 当前客户端连接正常,等待下次心跳
			if err != nil {
				return &models.DeviceStatus{
					Device:      o.device,
					State:       models.DeviceStateConnected,
					StateDetail: "重新连接",
				}, nil
			}
			return &models.DeviceStatus{
				Device:      o.device,
				State:       models.DeviceStateReconnecting,
				StateDetail: "连接正常",
			}, nil
		}
		return &models.DeviceStatus{
			Device:      o.device,
			State:       models.DeviceStateReconnecting,
			StateDetail: "重新连接",
		}, nil
	case <-o.ctx.Done(): //todo:如何确定opcua链接已经关闭
		hbTicker.Stop()
		return &models.DeviceStatus{
			Device:      o.device,
			State:       models.DeviceStateDisconnected,
			StateDetail: "连接已关闭",
		}, nil
	}
}

func (o *opcuaTwin) Read(propertyID models.ProductPropertyID) (map[models.ProductPropertyID]*models.DeviceData, error) {
	res := make(map[models.ProductPropertyID]*models.DeviceData)
	property, ok := o.properties[propertyID]
	if !ok {
		return nil, errors.NewCommonEdgeError(errors.NotFound, fmt.Sprintf("the property[%s] hasn't been ready", property.Id), nil)
	}
	readRsp, err := o.cli.Read(o.readReq)
	if err != nil {
		o.lg.Errorf(err.Error())
	}
	res[propertyID] = o.readRsp2DeviceData(readRsp)
	return res, err

}

func (o *opcuaTwin) Write(propertyID models.ProductPropertyID, values map[models.ProductPropertyID]*models.DeviceData) error {
	o.lg.Debugf("[%s]Write data :%+v", o.dvcID, values)
	// find the node id of corresponding property
	var props map[ProductPropID]interface{}

	if propertyID == models.DeviceDataMultiPropsID {
		ps, ok := values[propertyID].Value.(map[ProductPropID]interface{})
		if !ok {
			return errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("invalid multi write data %+v", values), nil)
		}
		props = ps
	} else {
		props = map[ProductPropID]interface{}{propertyID: values}
	}

	req, err := o.multiWriteReq(props)
	if err != nil {
		return errors.NewCommonEdgeError(errors.Driver, "failed to build multi write request", nil)
	}

	return o.write(req)
}

func (o *opcuaTwin) Subscribe(eventID models.ProductEventID, bus chan<- *models.DeviceDataWrapper) error {
	// 获取事件配置
	ec, ok := o.events[eventID]
	if !ok {
		return errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("opcua event '%s' not found in %+v", eventID, o.events), nil)
	}

	// 获取事件节点
	en := o.root.findNode(displayname2Nodeid[ec.Name])
	if en == nil {
		return errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("event node '%s' not found", en.id.String()), nil)
	}

	// 解析事件输出字段相关的OPCUA Node
	keys := make([]string, len(ec.Outs))      // 输出的字段名
	fields := make([]*TreeNode, len(ec.Outs)) // 输出的字段节点定义
	for i, o := range ec.Outs {
		// 假定OutputField.Id参数即为其在OPCUA中的 display name or browse name
		n, err := en.Child(o.Id)
		if err != nil {
			return errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("failed to get opcua node of event output '%s(%s)'", o.Name, o.Id), nil)
		}
		fields[i] = n
		keys[i] = o.Id
	}

	// 向服务器发送监控请求
	handle := uint32(len(o.evtHandles) + 1) // 标识本次Monitor
	req := o.eventRequest(handle, o.root.id, fields...)
	rsp, err := o.subscription.Monitor(ua.TimestampsToReturnBoth, req)
	if err != nil ||
		rsp == nil ||
		len(rsp.Results) == 0 ||
		rsp.Results[0].StatusCode != ua.StatusOK {
		return errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("failed to monitor event '%s'", eventID), nil)
	}

	// 设置时间回调函数
	o.evtHandles[handle] = func(values []*ua.Variant) {
		kvs := make(map[string]*models.DeviceData, len(ec.Outs))
		for i, key := range keys {
			kvs[key].Name = key
			kvs[key].Type = EventFunc
			kvs[key].Value = values[i].Value()
			kvs[key].Ts = time.Now()
		}
		bus <- &models.DeviceDataWrapper{
			DeviceID:   o.dvcID,
			ProductID:  o.pid,
			FuncID:     eventID,
			Properties: kvs,
		}
	}
	return nil
}

func (o *opcuaTwin) Call(methodID models.ProductMethodID, ins map[models.ProductPropertyID]*models.DeviceData) (outs map[models.ProductPropertyID]*models.DeviceData, err error) {
	mc, ok := o.methods[methodID]
	if !ok {
		return outs, errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf(
			"error while calling opcua device method, method %s not found", methodID), nil)
	}

	// build request
	req, err := o.callRequest(mc, ins)
	if err != nil {
		return outs, errors.NewCommonEdgeError(errors.Driver, "fail to get call request", nil)
	}

	// send request and get response
	resp, err := o.cli.Call(req)
	if err != nil {
		return outs, errors.NewCommonEdgeError(errors.Driver, "error while calling opcua device method, fail to get response", nil)
	}
	if got, want := resp.StatusCode, ua.StatusOK; got != want {
		return outs, errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("got status %v want %v", got, want), nil)
	}

	// build result
	if len(resp.OutputArguments) != len(mc.Outs) {
		return outs, errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf(
			"expect %d outputs params but received %d", len(mc.Outs), len(resp.OutputArguments)), nil)
	}
	for i, o := range mc.Outs {
		dd, _ := models.NewDeviceData(o.Name, DeviceResponse, resp.OutputArguments[i])
		outs[o.Id] = dd
	}
	return outs, nil
}

func (o *opcuaTwin) callRequest(mc *models.ProductMethod, ins map[models.ProductPropertyID]*models.DeviceData) (*ua.CallMethodRequest, error) {
	inputArguments := make([]*ua.Variant, len(mc.Ins))
	for i, inc := range mc.Ins {
		v := ins[inc.Id].Value
		if v == nil {
			return nil, errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf(
				"error while calling opcua device method, input param %s not found", inc.Id), nil)
		}
		input, err := ua.NewVariant(v)
		if err != nil {
			return nil, errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("failed to new variant with value: %+v", v), nil)
		}
		inputArguments[i] = input
	}

	mn := o.root.findNode(displayname2Nodeid[mc.Name])
	if mn == nil {
		return nil, errors.NotFound.Error("could not find current Node")
	}

	req := &ua.CallMethodRequest{
		ObjectID:       mn.Parent.id,
		MethodID:       mn.id,
		InputArguments: inputArguments,
	}
	return req, nil
}

// initClient 初始化OPCUA客户端
func (o *opcuaTwin) initClient() error {
	opts, err := o.opcuaDeviceConf.options()
	if err != nil {
		return err
	}

	o.cli = opcua.NewClient(o.opcuaDeviceConf.Endpoint, opts...)

	// connect opcua client
	o.lg.Debugf("start opcua client with config : %+v", o.opcuaDeviceConf)
	connCtx, _ := context.WithTimeout(o.ctx, DriverConnectTimeout)
	if err := o.cli.Connect(connCtx); err != nil {
		return err
	}
	return nil
}

// initReadReq 根据已有的属性配置, 将读取全量属性值的请求进行初始化并缓存, 供后续使用, 避免重复
func (o *opcuaTwin) initReadReq() {
	ns := make([]*ua.ReadValueID, 0)
	for _, pc := range o.product.Properties {
		ns = append(ns, &ua.ReadValueID{NodeID: displayname2Nodeid[pc.Name]})
	}
	o.readReq = &ua.ReadRequest{
		MaxAge:             2000,
		NodesToRead:        ns,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	}
}

func (o *opcuaTwin) initEvtSubscription() error {
	if o.cli == nil || o.ctx == nil || o.root == nil {
		return errors.NewCommonEdgeError(errors.DeviceTwin, "opcua driver has not initialized correctly", nil)
	}

	// 所有事件共用同一订阅实例, 初始MonitorItem为空
	notifyCh := make(chan *opcua.PublishNotificationData, EventQueueSize)
	s, err := o.cli.Subscribe(nil, notifyCh)
	if err != nil {
		return errors.NewCommonEdgeError(errors.Internal, "failed to init event subscription", nil)
	}
	o.subscription = s
	go s.Run(o.ctx) //
	go func() {
		for {
			select {
			case <-o.ctx.Done(): // 事件监听循环结束
				o.lg.Warnf("the event subscription of opcua driver has been closed")
				if err := s.Cancel(); err != nil {
					o.lg.Warnf("failed to cancel the subscription of opcua driver ")
				}
				return
			case notify := <-notifyCh: // 接收到通知
				// no event need to be handled
				if len(o.evtHandles) == 0 {
					continue
				}
				// ignore notifications which come from other Subscription
				if notify.SubscriptionID != s.SubscriptionID {
					continue
				}

				switch notify.Value.(type) {
				// only handle event notification
				case *ua.EventNotificationList:
					for _, evt := range notify.Value.(*ua.EventNotificationList).Events {
						handle, ok := o.evtHandles[evt.ClientHandle]
						if !ok {
							// event need not handled
							continue
						}
						// send event to its handler
						handle(evt.EventFields)
					}
				default:
					continue
				}
			}

		}

	}()
	return nil
}

func (o *opcuaDriver) write(req *ua.WriteRequest) error {
	// send write request
	rsp, err := o.cli.Write(req)
	if err != nil {
		return errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("failed to write node with req: '%+v'", req), nil)
	}

	// parse write rsp
	if rsp != nil && len(rsp.Results) != 0 {
		code := rsp.Results[0]
		if code != ua.StatusOK {
			return errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("failed to write node with req: '%+v'", req), nil)
		}
	}
	return nil
}

func (o *opcuaTwin) multiWriteReq(props map[ProductPropID]interface{}) (*ua.WriteRequest, error) {
	req := &ua.WriteRequest{
		NodesToWrite: make([]*ua.WriteValue, 0),
	}
	for _, pc := range o.product.Properties {
		value, ok := props[pc.Id]
		if !ok {
			continue
		}
		wv, err := o.newWriteValue(displayname2Nodeid[pc.Name], value)
		if err != nil {
			return nil, err
		}
		req.NodesToWrite = append(req.NodesToWrite, wv)
	}
	return req, nil
}

func (o *opcuaTwin) newWriteValue(nodeID *ua.NodeID, value interface{}) (*ua.WriteValue, error) {
	// new a variant
	v, err := ua.NewVariant(value)
	if err != nil {
		return nil, errors.NewCommonEdgeError(errors.Driver, fmt.Sprintf("failed to new variant with value: %+v", v), nil)
	}
	return &ua.WriteValue{
		NodeID:      nodeID,
		AttributeID: ua.AttributeIDValue,
		Value: &ua.DataValue{
			EncodingMask:    ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
			Value:           v,
			ServerTimestamp: time.Now(),
			SourceTimestamp: time.Now(),
		},
	}, nil
}

// eventRequest构建监控指定节点的事件的请求并返回
func (o *opcuaTwin) eventRequest(handle uint32, nodeID *ua.NodeID, fields ...*TreeNode) *ua.MonitoredItemCreateRequest {
	selects := make([]*ua.SimpleAttributeOperand, len(fields))
	for i, field := range fields {
		selects[i] = &ua.SimpleAttributeOperand{
			TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
			BrowsePath:       []*ua.QualifiedName{{NamespaceIndex: field.id.Namespace(), Name: field.Def.DisplayName}},
			AttributeID:      ua.AttributeIDValue,
		}
	}
	wheres := &ua.ContentFilter{
		Elements: []*ua.ContentFilterElement{
			{
				FilterOperator: ua.FilterOperatorGreaterThanOrEqual,
				FilterOperands: []*ua.ExtensionObject{
					{
						EncodingMask: 1,
						TypeID: &ua.ExpandedNodeID{
							NodeID: ua.NewNumericNodeID(0, id.SimpleAttributeOperand_Encoding_DefaultBinary),
						},
						Value: ua.SimpleAttributeOperand{
							TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
							BrowsePath:       []*ua.QualifiedName{{NamespaceIndex: 0, Name: "Severity"}},
							AttributeID:      ua.AttributeIDValue,
						},
					},
					{
						EncodingMask: 1,
						TypeID: &ua.ExpandedNodeID{
							NodeID: ua.NewNumericNodeID(0, id.LiteralOperand_Encoding_DefaultBinary),
						},
						Value: ua.LiteralOperand{
							Value: ua.MustVariant(uint16(0)),
						},
					},
				},
			},
		},
	}

	filter := ua.EventFilter{
		SelectClauses: selects,
		WhereClause:   wheres,
	}

	filterExtObj := ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID: &ua.ExpandedNodeID{
			NodeID: ua.NewNumericNodeID(0, id.EventFilter_Encoding_DefaultBinary),
		},
		Value: filter,
	}

	req := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:       nodeID,
			AttributeID:  ua.AttributeIDEventNotifier,
			DataEncoding: &ua.QualifiedName{},
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     handle,
			DiscardOldest:    true,
			Filter:           &filterExtObj,
			QueueSize:        10,
			SamplingInterval: 1.0,
		},
	}

	return req
}

func (o *opcuaTwin) readRsp2DeviceData(rsp *ua.ReadResponse) *models.DeviceData {
	data := &models.DeviceData{
		Name: o.device.ID,
		Type: DeviceRead,
		Ts:   time.Now(),
	}
	res := make([]interface{}, len(rsp.Results))

	for _, v := range rsp.Results {
		if v.Status != ua.StatusOK {
			continue
		}
		res = append(res, v.Value.Value())
	}
	data.Value = res
	return data
}

// options 将用户指定的设备配置转换为opcua client的配置选项
func (c opcuaDeviceConf) options() ([]opcua.Option, error) {
	endpoints, err := getEndpointsWithTimeout(c.Endpoint, DriverConnectTimeout)
	if err != nil {
		return nil, err
	}
	if len(endpoints) < 1 {
		return nil, errors.NewCommonEdgeError(errors.Internal, "there is no endpoint ", nil)
	}

	var opts []opcua.Option
	// 公钥所在文件路径
	if c.CertFile != "" {
		opts = append(opts, opcua.CertificateFile(c.CertFile))
	}
	// 私钥所在文件路径
	if c.KeyFile != "" {
		opts = append(opts, opcua.PrivateKeyFile(c.KeyFile))
	}
	if c.ScMode != "" {
		opts = append(opts, opcua.SecurityModeString(c.ScMode))
	}
	if c.ScPolicy != "" {
		opts = append(opts, opcua.SecurityPolicy(c.ScPolicy))
	}
	if c.UserName != "" {
		opts = append(opts, opcua.AuthUsername(c.UserName, c.Password))
		opts = append(opts, opcua.SecurityFromEndpoint(endpoints[0], ua.UserTokenTypeUserName))
	}
	return opts, nil
}

func (o *opcuaTwin) ping() error {
	_, err := o.cli.GetEndpoints()
	return err
}

func getEndpointsWithTimeout(endpoint string, timeout time.Duration) ([]*ua.EndpointDescription, error) {
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	c := opcua.NewClient(endpoint)
	if err := c.Dial(ctx); err != nil {
		return nil, err
	}
	defer c.Close()
	res, err := c.GetEndpoints()
	if err != nil {
		return nil, err
	}
	return res.Endpoints, nil
}
