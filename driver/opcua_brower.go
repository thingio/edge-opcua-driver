package driver

import (
	"fmt"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/thingio/edge-device-std/errors"
	"github.com/thingio/edge-device-std/models"

	"strings"
)

type MyNodeDef struct {
	NodeClass   ua.NodeClass
	DisplayName string
}

// SetAttr 将依据指定的属性类型ID, 设置其对应的值
func (n *MyNodeDef) SetAttr(attrID ua.AttributeID, attr *ua.DataValue) {
	switch attrID {
	case ua.AttributeIDNodeClass:
		n.NodeClass = ua.NodeClass(attr.Value.Int())
	case ua.AttributeIDDisplayName:
		n.DisplayName = attr.Value.String()
	}
}

type TreeNode struct {
	//node        *opcua.Node
	id       *ua.NodeID
	c        *opcua.Client
	Def      *MyNodeDef
	Parent   *TreeNode
	RefType  uint32 // 当前节点与父节点之间的关系
	Children []*TreeNode
}

func NewTreeNode(c *opcua.Client, id *ua.NodeID) *TreeNode {
	return &TreeNode{
		id:       id,
		c:        c,
		Def:      &MyNodeDef{},
		Children: make([]*TreeNode, 0),
	}
}

func (n *TreeNode) FindByDisplayName(displayName string) (*TreeNode, error) {
	if n.Def.DisplayName == displayName {
		return n, nil
	}
	if len(n.Children) == 0 {
		return nil, nil
	}
	for _, child := range n.Children {
		res, _ := child.FindByDisplayName(displayName)
		if res != nil {
			return res, nil
		}
	}
	return nil, errors.NotFound.Error(
		"node with display name '%s' not found in tree '%s'", displayName, n.Def.DisplayName)
}

// DisplayNames 返回当前节点及其所有子节点的 DisplayName -> NodeID 的映射
func (n *TreeNode) DisplayNames() map[string]*ua.NodeID {
	names := make(map[string]*ua.NodeID)
	names[n.Def.DisplayName] = n.id
	if len(n.Children) == 0 {
		return names
	}
	for _, child := range n.Children {
		childNames := child.DisplayNames()
		for name, nodeID := range childNames {
			if _, ok := names[name]; ok {
				//logger.NewLogger("skip opcua node '%s' cause it's display name '%s' already existed"+
				//"prev node id is '%s'", nodeID.String(), name, prev.String())
				continue //todo: 如何打log
			}
			names[name] = nodeID
		}
	}
	return names
}

// PropsConf 返回当前节点及其所有子节点的 propConf 数组
func (n *TreeNode) PropsConf() []*models.ProductProperty {
	conf := make([]*models.ProductProperty, 0)
	if n.Def.NodeClass == ua.NodeClassVariable {
		conf = append(conf, n.propConf())
	}
	if len(n.Children) == 0 {
		return conf
	}
	for _, child := range n.Children {
		childConf := child.PropsConf()
		conf = append(conf, childConf...)
	}
	return conf
}

// propConf 返回一个节点响应的属性配置
func (n *TreeNode) propConf() *models.ProductProperty {
	m := map[string]string{
		n.Def.DisplayName: n.id.String(),
	}
	return &models.ProductProperty{
		Id:         n.Def.DisplayName,
		Name:       n.Def.DisplayName,
		ReportMode: RegularMode,
		Interval:   "0",
		AuxProps:   m,
	}
}

// Build 将以当前节点为根, 遍历其所有子节点, 并构建为树状
func (n *TreeNode) Build() error {
	// 若当前节点为Variable类型,则认为该节点为叶节点
	if n.Def.NodeClass == ua.NodeClassVariable {
		return nil
	}

	refs, err := n.ReferencedNodes()
	if err != nil {
		return err
	}
	n.Children = refs
	for _, rn := range refs {
		// NOTICE 此处将变量类型的节点默认为叶节点, 若有需要可进行修改
		if rn.Def.NodeClass == ua.NodeClassVariable {
			continue
		}
		if _, ok := refTypes[rn.RefType]; !ok {
			continue
		}
		if err := rn.Build(); err != nil {
			return err
		}
	}
	return nil
}

var refTypes = map[uint32]struct{}{
	id.HasComponent:   {}, // 包含的属性/事件/方法
	id.Organizes:      {}, // 包含的文件夹/对象
	id.HasProperty:    {}, // 包含的属性
	id.GeneratesEvent: {}, // 包含的事件
}

// ReferencedNodes 返回与当前节点相关的节点
func (n *TreeNode) ReferencedNodes() ([]*TreeNode, error) {
	req := &ua.BrowseRequest{
		RequestHeader: nil,
		View: &ua.ViewDescription{
			ViewID: ua.NewTwoByteNodeID(0),
		},
		RequestedMaxReferencesPerNode: 0,
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          n.id,
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.References),
			IncludeSubtypes: true,
			NodeClassMask:   uint32(ua.NodeClassAll),
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
	}
	rsp, err := n.c.Browse(req)
	if err != nil {
		return nil, errors.Internal.Cause(err, "failed to browse opcua with req %+v", req)
	}
	if code := rsp.Results[0].StatusCode; code != ua.StatusOK {
		return nil, errors.Internal.Cause(code, "failed to browse opcua with req %+v", req)
	}

	refs := rsp.Results[0].References
	nodes := make([]*TreeNode, len(refs))
	for idx, ref := range refs {
		nid, err := ua.ParseNodeID(ref.NodeID.String())
		if err != nil {
			// it shouldn't happen
			return nil, errors.Internal.Cause(err, "failed to parse opcua id %s", ref.NodeID.String())
		}
		nodes[idx] = &TreeNode{
			id: nid,
			c:  n.c,
			Def: &MyNodeDef{
				NodeClass:   ref.NodeClass,
				DisplayName: ref.DisplayName.Text,
			},
			Parent:  n,
			RefType: ref.ReferenceTypeID.IntID(),
		}
	}
	return nodes, nil
}

// FindNodeByPath 通过节点路径查找相应的OPCUA Node
func (o *opcuaDriver) FindNodeByPath(path string) (*TreeNode, error) {
	names := strings.Split(path, NodePathSep)
	if len(names) <= 1 || names[0] != NodePathPrefix {
		return nil, errors.Internal.Error("invalid opcua device node path '%s'", path)
	}

	root := NewTreeNode(o.cli, ua.NewTwoByteNodeID(id.ObjectsFolder))
	for idx, name := range names[1:] {
		node, err := root.Child(name)
		if err != nil {
			return nil, errors.NewCommonEdgeError(errors.Configuration, fmt.Sprintf("failed to find node by path '%s'", strings.Join(names[:idx], NodePathSep)), nil)
		}
		root = node
	}
	return root, nil
}

// Child 根据指定的DisplayName返回当前节点的子节点
func (n *TreeNode) Child(displayName string) (*TreeNode, error) {
	if n.Children == nil || len(n.Children) == 0 {
		children, err := n.ReferencedNodes()
		if err != nil {
			return nil, errors.Internal.Error("failed to get reference nodes of node '%s'", n.id.String())
		}
		n.Children = children
	}

	// 遍历所有子节点
	for _, child := range n.Children {
		if child.Def.DisplayName == displayName {
			return child, nil
		}
	}
	return nil, errors.Internal.Error("child node named '%s' of '%s' not found", displayName, n.id.String())
}

// findNode 根据指定的nodeID找到对应的当前节点
func (n *TreeNode) findNode(nodeID *ua.NodeID) *TreeNode {
	if n.id == nodeID {
		return n
	}
	if len(n.Children) == 0 {
		return nil
	}
	for _, child := range n.Children {
		n := child.findNode(nodeID)
		if n != nil {
			return n
		}
	}
	return nil
}
