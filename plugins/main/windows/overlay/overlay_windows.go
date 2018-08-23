// Copyright 2017 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"strings"

	"github.com/juju/errors"

	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/hns"
	"github.com/containernetworking/plugins/pkg/ipam"
)

type NetConf struct {
	hns.NetConf

	IPMasq            bool   `json:"ipMasq"`
	EndpointMacPrefix string `json:"endpointMacPrefix,omitempty"`
}

type K8sCniEnvArgs struct {
	types.CommonArgs

	PodNamespace types.UnmarshallableString `json:"K8S_POD_NAMESPACE,omitempty"`
	// PodName             types.UnmarshallableString `json:"K8S_POD_NAME,omitempty"`
	// PodInfraContainerID types.UnmarshallableString `json:"K8S_POD_INFRA_CONTAINER_ID,omitempty"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func parseCniArgs(args string) (*K8sCniEnvArgs, error) {
	podConfig := K8sCniEnvArgs{}
	err := types.LoadArgs(args, &podConfig)
	if err != nil {
		return nil, err
	}
	return &podConfig, nil
}

func loadNetConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", errors.Annotatef(err, "failed to load netconf")
	}
	return n, n.CNIVersion, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Printf("[cni-net] Processing ADD command with args {ContainerID:%v Netns:%v IfName:%v Args:%v Path:%v}.",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)

	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return errors.Annotate(err, "error while loadNetConf")
	}

	cniargs, err := parseCniArgs(args.Args)
	if err != nil {
		return errors.Annotate(err, "error while parseCniArgs")
	}

	k8sNamespace := "default"
	if len(cniargs.PodNamespace) != 0 {
		k8sNamespace = string(cniargs.PodNamespace)
	}

	if n.EndpointMacPrefix != "" {
		if len(n.EndpointMacPrefix) != 5 || n.EndpointMacPrefix[2] != '-' {
			return fmt.Errorf("endpointMacPrefix [%v] is invalid, value must be of the format xx-xx", n.EndpointMacPrefix)
		}
	} else {
		n.EndpointMacPrefix = "0E-2A"
	}

	networkName := n.Name
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return errors.Annotatef(err, "error while GETHNSNewtorkByName(%f)", networkName)
	}

	if hnsNetwork == nil {
		return fmt.Errorf("network %v not found", networkName)
	}

	if !strings.EqualFold(hnsNetwork.Type, "Overlay") {
		return fmt.Errorf("network %v is of an unexpected type: %v", networkName, hnsNetwork.Type)
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	hnsEndpoint, err := hns.ProvisionEndpoint(epName, hnsNetwork.Id, args.ContainerID, func() (*hcsshim.HNSEndpoint, error) {
		// run the IPAM plugin and get back the config to apply
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return nil, errors.Annotatef(err, "error while ipam.ExecAdd")
		}

		// Convert whatever the IPAM result was into the current Result type
		result, err := current.NewResultFromResult(r)
		if err != nil {
			return nil, errors.Annotatef(err, "error while NewResultFromResult")
		}

		if len(result.IPs) == 0 {
			return nil, errors.New("IPAM plugin return is missing IP config")
		}

		ipAddr := result.IPs[0].Address.IP.To4()
		// conjure a MAC based on the IP for Overlay
		macAddr := fmt.Sprintf("%v-%02x-%02x-%02x-%02x", n.EndpointMacPrefix, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
		// use the HNS network gateway
		gw := hnsNetwork.Subnets[0].GatewayAddress
		n.ApplyDefaultPAPolicy(hnsNetwork.ManagementIP)
		if n.IPMasq {
			n.ApplyOutboundNatPolicy(hnsNetwork.Subnets[0].AddressPrefix)
		}

		nameservers := strings.Join(n.DNS.Nameservers, ",")
		if result.DNS.Nameservers != nil {
			nameservers = strings.Join(result.DNS.Nameservers, ",")
		}

		dnsSuffix := ""
		if len(n.DNS.Search) > 0 {
			dnsSuffix = k8sNamespace + "." + n.DNS.Search[0]
		}

		hnsEndpoint := &hcsshim.HNSEndpoint{
			Name:           epName,
			VirtualNetwork: hnsNetwork.Id,
			DNSServerList:  nameservers,
			DNSSuffix:      dnsSuffix,
			GatewayAddress: gw,
			IPAddress:      ipAddr,
			MacAddress:     macAddr,
			Policies:       n.MarshalPolicies(),
		}

		log.Printf("Adding Hns Endpoint %v", hnsEndpoint)
		return hnsEndpoint, nil
	})
	if err != nil {
		return errors.Annotatef(err, "error while ProvisionEndpoint(%v,%v,%v)", epName, hnsNetwork.Id, args.ContainerID)
	}

	result, err := hns.ConstructResult(hnsNetwork, hnsEndpoint)
	if err != nil {
		return errors.Annotatef(err, "error while constructResult")
	}

	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	log.Printf("[cni-net] Processing DEL command with args {ContainerID:%v Netns:%v IfName:%v Args:%v Path:%v}.",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)

	n, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	return hns.DeprovisionEndpoint(epName, args.Netns, args.ContainerID)
}

func cmdGet(args *skel.CmdArgs) error {
	// TODO: implement
	return fmt.Errorf("not implemented")
}

func main() {
	skel.PluginMain(cmdAdd, cmdGet, cmdDel, version.All, "TODO")
}
