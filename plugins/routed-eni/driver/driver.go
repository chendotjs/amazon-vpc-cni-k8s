// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package driver

import (
	"net"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/vishvananda/netlink"

	log "github.com/cihub/seelog"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/ipwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/networkutils"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper"
)

const (
	// ip rules priority and leave 512 gap for future
	toContainerRulePriority = 512
	// 1024 is reserved for (ip rule not to <vpc's subnet> table main)
	fromContainerRulePriority = 1536

	// main routing table number
	mainRouteTable = unix.RT_TABLE_MAIN
	// MTU of veth - ENI MTU defined in pkg/networkutils/network.go
	ethernetMTU = 9001
)

// NetworkAPIs defines network API calls
type NetworkAPIs interface {
	SetupNS(hostVethName string, contVethName string, netnsPath string, addr *net.IPNet, table int, vpcCIDRs []string, useExternalSNAT bool) error
	TeardownNS(addr *net.IPNet, table int) error
}

type linuxNetwork struct {
	netLink netlinkwrapper.NetLink
	ns      nswrapper.NS
}

// New creates linuxNetwork object
func New() NetworkAPIs {
	return &linuxNetwork{
		netLink: netlinkwrapper.NewNetLink(),
		ns:      nswrapper.NewNS(),
	}
}

// createVethPairContext wraps the parameters and the method to create the
// veth pair to attach the container namespace
// 创建veth pair需要hostveth和contveth以及contveth的IP地址
type createVethPairContext struct {
	contVethName string
	hostVethName string
	addr         *net.IPNet
	netLink      netlinkwrapper.NetLink // vishvananda的netlink
	ip           ipwrapper.IP // 设置默认路由
}

func newCreateVethPairContext(contVethName string, hostVethName string, addr *net.IPNet) *createVethPairContext {
	return &createVethPairContext{
		contVethName: contVethName,
		hostVethName: hostVethName,
		addr:         addr,
		netLink:      netlinkwrapper.NewNetLink(),
		ip:           ipwrapper.NewIP(),
	}
}

// run defines the closure to execute within the container's namespace to
// create the veth pair
// 创建veth pair，设置路由规则，并将host veth放到rootns中
// 这个函数会在pod的netns中执行
func (createVethContext *createVethPairContext) run(hostNS ns.NetNS) error {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  createVethContext.contVethName,
			Flags: net.FlagUp,
			MTU:   ethernetMTU,
		},
		PeerName: createVethContext.hostVethName,
	}

	// 创建veth设备对
	if err := createVethContext.netLink.LinkAdd(veth); err != nil {
		return err
	}

	// 检查hostveth
	hostVeth, err := createVethContext.netLink.LinkByName(createVethContext.hostVethName)
	if err != nil {
		return errors.Wrapf(err, "setup NS network: failed to find link %q", createVethContext.hostVethName)
	}

	// Explicitly set the veth to UP state, because netlink doesn't always do that on all the platforms with net.FlagUp.
	// veth won't get a link local address unless it's set to UP state.
	if err = createVethContext.netLink.LinkSetUp(hostVeth); err != nil {
		return errors.Wrapf(err, "setup NS network: failed to set link %q up", createVethContext.hostVethName)
	}

	// 检查contveth
	contVeth, err := createVethContext.netLink.LinkByName(createVethContext.contVethName)
	if err != nil {
		return errors.Wrapf(err, "setup NS network: failed to find link %q", createVethContext.contVethName)
	}

	// Explicitly set the veth to UP state, because netlink doesn't always do that on all the platforms with net.FlagUp.
	// veth won't get a link local address unless it's set to UP state.
	if err = createVethContext.netLink.LinkSetUp(contVeth); err != nil {
		return errors.Wrapf(err, "setup NS network: failed to set link %q up", createVethContext.contVethName)
	}

	// Add a connected route to a dummy next hop (169.254.1.1)
	// # ip route show
	// default via 169.254.1.1 dev eth0
	// 169.254.1.1 dev eth0
	gw := net.IPv4(169, 254, 1, 1)
	gwNet := &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)}

	// 添加静态路由 ip route add 169.254.1.1/32 dev eth0 scope link
	// man ip-link 说：
	// the scope of the destinations covered by the route prefix.  SCOPE_VAL may be a number or a string from the file /etc/iproute2/rt_scopes.  If this parameter is omitted, ip assumes scope global for all gatewayed unicast routes, scope link for
	//                     direct unicast and broadcast routes and scope host for local routes.
	if err = createVethContext.netLink.RouteReplace(&netlink.Route{
		LinkIndex: contVeth.Attrs().Index,
		Scope:     netlink.SCOPE_LINK, // TODO: hostveth和contveth直连，所以用SCOPE_LINK？对比ip.AddHostRoute和ip.AddRoute
		Dst:       gwNet}); err != nil {
		return errors.Wrap(err, "setup NS network: failed to add default gateway")
	}

	// Add a default route via dummy next hop(169.254.1.1). Then all outgoing traffic will be routed by this
	// default route via dummy next hop (169.254.1.1).
	// 添加默认路由 ip route add default via 169.254.1.1 dev eth0
	if err = createVethContext.ip.AddDefaultRoute(gwNet.IP, contVeth); err != nil {
		return errors.Wrap(err, "setup NS network: failed to add default route")
	}

	// 设置contveth的IP地址，这里的IP由IPAMD传来
	if err = createVethContext.netLink.AddrAdd(contVeth, &netlink.Addr{IPNet: createVethContext.addr}); err != nil {
		return errors.Wrapf(err, "setup NS network: failed to add IP addr to %q", createVethContext.contVethName)
	}

	// add static ARP entry for default gateway
	// we are using routed mode on the host and container need this static ARP entry to resolve its default gateway.
	// 效果类似 arp -s 169.254.1.1 hsotveth.mac
	neigh := &netlink.Neigh{
		LinkIndex:    contVeth.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           gwNet.IP,
		HardwareAddr: hostVeth.Attrs().HardwareAddr,
	}

	// ip neighbor del 169.254.1.1 lladdr hsotveth.mac dev eth0 nud permanent
	if err = createVethContext.netLink.NeighAdd(neigh); err != nil {
		return errors.Wrap(err, "setup NS network: failed to add static ARP")
	}

	// Now that the everything has been successfully set up in the container, move the "host" end of the
	// veth into the host namespace.
	// 移veth到rootns
	if err = createVethContext.netLink.LinkSetNsFd(hostVeth, int(hostNS.Fd())); err != nil {
		return errors.Wrap(err, "setup NS network: failed to move veth to host netns")
	}
	return nil
}

// SetupNS wires up linux networking for a pod's network
func (os *linuxNetwork) SetupNS(hostVethName string, contVethName string, netnsPath string, addr *net.IPNet, table int, vpcCIDRs []string, useExternalSNAT bool) error {
	log.Debugf("SetupNS: hostVethName=%s,contVethName=%s, netnsPath=%s table=%d\n", hostVethName, contVethName, netnsPath, table)
	return setupNS(hostVethName, contVethName, netnsPath, addr, table, vpcCIDRs, useExternalSNAT, os.netLink, os.ns)
}

func setupNS(hostVethName string, contVethName string, netnsPath string, addr *net.IPNet, table int, vpcCIDRs []string, useExternalSNAT bool,
	netLink netlinkwrapper.NetLink, ns nswrapper.NS) error {
	// Clean up if hostVeth exists.
	// 如果rootns存在同一个container遗留的veth就删掉
	if oldHostVeth, err := netLink.LinkByName(hostVethName); err == nil {
		if err = netLink.LinkDel(oldHostVeth); err != nil {
			return errors.Wrapf(err, "setupNS network: failed to delete old hostVeth %q", hostVethName)
		}
		log.Debugf("Clean up old hostVeth: %v\n", hostVethName)
	}

	createVethContext := newCreateVethPairContext(contVethName, hostVethName, addr)
	// 在Pod netns中创建veth pair，设置Pod eth0的IP以及网关路由规则，并将host veth放到rootns中
	if err := ns.WithNetNSPath(netnsPath, createVethContext.run); err != nil {
		log.Errorf("Failed to setup NS network %v", err)
		return errors.Wrap(err, "setupNS network: failed to setup NS network")
	}

	hostVeth, err := netLink.LinkByName(hostVethName)
	if err != nil {
		return errors.Wrapf(err, "setupNS network: failed to find link %q", hostVethName)
	}

	// Explicitly set the veth to UP state, because netlink doesn't always do that on all the platforms with net.FlagUp.
	// veth won't get a link local address unless it's set to UP state.
	if err = netLink.LinkSetUp(hostVeth); err != nil {
		return errors.Wrapf(err, "setupNS network: failed to set link %q up", hostVethName)
	}

	log.Debugf("Setup host route outgoing hostVeth, LinkIndex %d\n", hostVeth.Attrs().Index)
	addrHostAddr := &net.IPNet{
		IP:   addr.IP,
		Mask: net.CIDRMask(32, 32)}

	// Add host route
	route := netlink.Route{
		LinkIndex: hostVeth.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       addrHostAddr}

	// Add or replace route
	// 设置 ip route replace `PodIP` dev `hostveth` scope link
	if err := netLink.RouteReplace(&route); err != nil {
		return errors.Wrapf(err, "setupNS: unable to add or replace route entry for %s", route.Dst.IP.String())
	}
	log.Debugf("Successfully set host route to be %s/0", route.Dst.IP.String())

	// 设置：ip rule add to `PodIP` lookup main prio 512
	toContainerFlag := true
	err = addContainerRule(netLink, toContainerFlag, addr, toContainerRulePriority, mainRouteTable)

	if err != nil {
		log.Errorf("Failed to add toContainer rule for %s err=%v, ", addr.String(), err)
		return errors.Wrap(err, "setupNS network: failed to add toContainer")
	}

	log.Infof("Added toContainer rule for %s", addr.String())

	// add from-pod rule, only need it when it is not primary ENI
	if table > 0 {
		if useExternalSNAT {
			// add rule: 1536: from <podIP> use table <table>
			// 每个eni都有一个唯一的table
			// 设置：ip rule add from `PodIP` lookup `eni-table` prio 1536
			toContainerFlag = false
			err = addContainerRule(netLink, toContainerFlag, addr, fromContainerRulePriority, table)

			if err != nil {
				log.Errorf("Failed to add fromContainer rule for %s err: %v", addr.String(), err)
				return errors.Wrap(err, "add NS network: failed to add fromContainer rule")
			}
			log.Infof("Added rule priority %d from %s table %d", fromContainerRulePriority, addr.String(), table)
		} else {
			// add rule: 1536: list of from <podIP> to <vpcCIDR> use table <table>
			for _, cidr := range vpcCIDRs {
				podRule := netLink.NewRule()
				_, podRule.Dst, _ = net.ParseCIDR(cidr)
				podRule.Src = addr
				podRule.Table = table
				podRule.Priority = fromContainerRulePriority

				err = netLink.RuleAdd(podRule)
				if isRuleExistsError(err) {
					log.Warn("Rule already exists [%v]", podRule)
				} else {
					if err != nil {
						log.Errorf("Failed to add pod IP rule [%v]: %v", podRule, err)
						return errors.Wrapf(err, "setupNS: failed to add pod rule [%v]", podRule)
					}
				}
				var toDst string

				if podRule.Dst != nil {
					toDst = podRule.Dst.String()
				}
				log.Infof("Successfully added pod rule[%v] to %s", podRule, toDst)
			}
		}
	}
	return nil
}

// addr传递进来的是PodIP
func addContainerRule(netLink netlinkwrapper.NetLink, isToContainer bool, addr *net.IPNet, priority int, table int) error {
	containerRule := netLink.NewRule()

	// containerRule的Dst和Src决定了table的条件（from或to）
	if isToContainer {
		containerRule.Dst = addr // ip rule add from all to `addr` lookup `table` prio `xxx`
	} else {
		containerRule.Src = addr // ip rule add from `addr` lookup `table` prio `xxx`
	}
	containerRule.Table = table
	containerRule.Priority = priority

	// 清理旧策略规则 设置 ip rule del
	err := netLink.RuleDel(containerRule)
	if err != nil && !containsNoSuchRule(err) {
		return errors.Wrapf(err, "addContainerRule: failed to delete old container rule for %s", addr.String())
	}

	// 设置 ip rule add ... dev  `table` prio `xxx`
	err = netLink.RuleAdd(containerRule)
	if err != nil {
		return errors.Wrapf(err, "addContainerRule: failed to add container rule for %s", addr.String())
	}
	return nil
}

// TeardownPodNetwork cleanup ip rules
func (os *linuxNetwork) TeardownNS(addr *net.IPNet, table int) error {
	log.Debugf("TeardownNS: addr %s, table %d", addr.String(), table)
	return tearDownNS(addr, table, os.netLink)
}

// addr为待删除的PodIP
func tearDownNS(addr *net.IPNet, table int, netLink netlinkwrapper.NetLink) error {
	// remove to-pod rule
	// 设置 ip rule del to `PodIP` (table main) prio 512
	toContainerRule := netLink.NewRule()
	toContainerRule.Dst = addr
	toContainerRule.Priority = toContainerRulePriority
	err := netLink.RuleDel(toContainerRule)

	if err != nil {
		log.Errorf("Failed to delete toContainer rule for %s err %v", addr.String(), err)
	} else {
		log.Infof("Delete toContainer rule for %s ", addr.String())
	}

	if table > 0 {
		// remove from-pod rule only for non main table
		// 设置 ip rule del from `PodIP`
		err := deleteRuleListBySrc(*addr)
		if err != nil {
			log.Errorf("Failed to delete fromContainer for %s %v", addr.String(), err)
			return errors.Wrapf(err, "delete NS network: failed to delete fromContainer rule for %s", addr.String())
		}
		log.Infof("Delete fromContainer rule for %s in table %d", addr.String(), table)
	}

	addrHostAddr := &net.IPNet{
		IP:   addr.IP,
		Mask: net.CIDRMask(32, 32)}

	// cleanup host route:
	// 设置 ip route del `PodIP`
	if err = netLink.RouteDel(&netlink.Route{
		Scope: netlink.SCOPE_LINK,
		Dst:   addrHostAddr}); err != nil {
		log.Errorf("delete NS network: failed to delete host route for %s, %v", addr.String(), err)
	}
	return nil
}
// deleteRuleListBySrc 删除源地址为src的所有rule
func deleteRuleListBySrc(src net.IPNet) error {
	networkClient := networkutils.New()
	return networkClient.DeleteRuleListBySrc(src)
}

func containsNoSuchRule(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.ENOENT
	}
	return false
}

func isRuleExistsError(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.EEXIST
	}
	return false
}
