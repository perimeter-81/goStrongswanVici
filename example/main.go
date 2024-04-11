package main

import (
	"fmt"
	"net"
	"time"

	"github.com/perimeter-81/goStrongswanVici"
)

func main() {
	// create a client.
	addr, err2 := net.ResolveTCPAddr("tcp", "localhost:8555")
	if err2 != nil {
		panic(err2)
	}
	conn, err3 := net.DialTCP("tcp", nil, addr)
	if err3 != nil {
		panic(err3)
	}
	client := goStrongswanVici.NewClientConn(conn)
	defer client.Close()

	// get strongswan version
	v, err := client.Version()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", v)
	go func() {
		err = client.MonitorSA(func(event string, info interface{}) {
			fmt.Printf("event %q; content:%+v\n", event, info)
		}, 1*time.Second)
		if err != nil {
			fmt.Printf("failed setting monitor sa: %v", err)
			// panic(err)
		}
	}()

	client.Terminate(&goStrongswanVici.TerminateRequest{
		Child:    "",
		Ike:      "test-connection",
		Child_id: "",
		Ike_id:   "",
		Force:    "true",
		Timeout:  "-1",
		Loglevel: "",
	})

	client.Terminate(&goStrongswanVici.TerminateRequest{
		Child:    "",
		Ike:      "test-connection-1",
		Child_id: "",
		Ike_id:   "",
		Force:    "true",
		Timeout:  "-1",
		Loglevel: "",
	})

	childConfMap := make(map[string]goStrongswanVici.ChildSAConf)
	childSAConf := goStrongswanVici.ChildSAConf{
		LocalTs:       []string{"10.10.59.0/24"},
		RemoteTs:      []string{"10.10.40.0/24"},
		ESPProposals:  []string{"aes256-sha256-modp2048"},
		StartAction:   "start",
		CloseAction:   "restart",
		ReqID:         "10",
		RekeyTime:     "10m",
		ReplayWindow:  "",
		Mode:          "tunnel",
		InstallPolicy: "no",
	}
	childConfMap["test-child-conn"] = childSAConf
	localAuthConf := goStrongswanVici.AuthConf{
		AuthMethod: "psk",
		ID:         "192.168.198.16",
	}
	remoteAuthConf := goStrongswanVici.AuthConf{
		AuthMethod: "psk",
		ID:         "192.168.198.11",
	}
	ikeConfMap := make(map[string]goStrongswanVici.IKEConf)
	ikeConf := goStrongswanVici.IKEConf{
		LocalAddrs:  []string{"192.168.198.16"},
		RemoteAddrs: []string{"192.168.198.11"},
		LocalPort:   "",
		RemotePort:  "",
		Proposals:   []string{"aes256-sha256-modp2048"},
		Vips:        nil,
		Version:     "2",
		Encap:       true,
		KeyingTries: "",
		RekeyTime:   "",
		DPDDelay:    "30s",
		DPDTimeout:  "34s",
		LocalAuth:   localAuthConf,
		RemoteAuth:  remoteAuthConf,
		Pools:       nil,
		Children:    childConfMap,
		Mobike:      false,
	}

	ikeConfMap["test-connection"] = ikeConf

	childConfMap1 := make(map[string]goStrongswanVici.ChildSAConf)
	childSAConf1 := goStrongswanVici.ChildSAConf{
		LocalTs:       []string{"10.10.59.0/24"},
		RemoteTs:      []string{"10.10.40.0/24"},
		ESPProposals:  []string{"aes256-sha256-modp2048"},
		StartAction:   "start",
		CloseAction:   "restart",
		ReqID:         "10",
		RekeyTime:     "10m",
		ReplayWindow:  "",
		Mode:          "tunnel",
		InstallPolicy: "no",
	}
	childConfMap1["test-child-conn-1"] = childSAConf1
	ikeConf1 := goStrongswanVici.IKEConf{
		LocalAddrs:  []string{"192.168.198.9"},
		RemoteAddrs: []string{"192.168.198.8"},
		LocalPort:   "",
		RemotePort:  "",
		Proposals:   []string{"aes256-sha256-modp2048"},
		Vips:        nil,
		Version:     "1",
		Encap:       true,
		KeyingTries: "",
		RekeyTime:   "",
		DPDDelay:    "4s",
		DPDTimeout:  "36s",
		LocalAuth:   localAuthConf,
		RemoteAuth:  remoteAuthConf,
		Pools:       nil,
		Children:    childConfMap1,
		Mobike:      true,
	}
	ikeConfMap["test-connection-1"] = ikeConf1

	// load connenction information into strongswan
	err = client.LoadConn(&ikeConfMap)
	if err != nil {
		fmt.Printf("error loading connection: %w", err)
		panic(err)
	}

	sharedKey := &goStrongswanVici.Key{
		ID:     "192.168.198.16",
		Typ:    "IKE",
		Data:   "this is the key",
		Secret: "this is the key",
		Owners: []string{
			"192.168.198.16",
			"192.168.198.11",
		},
	}

	// load shared key into strongswan
	err = client.LoadShared(sharedKey)
	if err != nil {
		fmt.Printf("error returned from loadsharedkey \n")
		panic(err)
	}

	// list-conns
	connList, err := client.ListConns("")
	if err != nil {
		fmt.Printf("error list-conns: %v \n", err)
	}

	for id, connectionMap := range connList {
		fmt.Printf("\n\n connection map %d: \n", id)
		for key, connection := range connectionMap {
			fmt.Printf("\n tunnel ID: %q \n", key)
			fmt.Printf("\n\n connection details: \n %+v \n", connection)
		}
	}

	fmt.Printf("\n expected connections %+v", ikeConfMap)

	fmt.Printf("\n\n list sas: \n")

	sas, err := client.ListSas("", "")
	if err != nil {
		fmt.Printf("error ListSas: %v \n", err)
	}

	for id, connectionMap := range sas {
		fmt.Printf("\n\n connection map %d: \n", id)
		for key, connection := range connectionMap {
			fmt.Printf("\n\n connection %q: \n %+v \n", key, connection)
		}
	}

	fmt.Printf("\n\n list secrets: \n")
	secrets, err := client.GetShared()
	if err != nil {
		fmt.Printf("error GetShared: %v \n", err)
	}

	fmt.Printf("secrets: %+v \n", secrets)
	fmt.Printf("expected secrets: %+v \n", sharedKey.Data)

	// fmt.Printf("\n\n init: \n")
	//
	// if err := client.Terminate(&goStrongswanVici.TerminateRequest{
	// 	Child:    "test-child-conn",
	// 	Ike:      "test-connection",
	// 	Child_id: "",
	// 	Ike_id:   "",
	// 	Force:    "true",
	// 	Timeout:  "30s",
	// 	Loglevel: "4",
	// }); err != nil {
	// 	fmt.Printf("error terminate: %v \n", err)
	// }
	// if err := client.Initiate("test-child-conn", "test-connection"); err != nil {
	// 	fmt.Printf("error Initiate: %v \n", err)
	// }
	//
	// // get all conns info from strongswan
	// connInfo, err := client.ListAllVpnConnInfo()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("found %d vpn connections. \n", len(connInfo))
	// fmt.Printf("VPNconnInfo: %+v\n", connInfo)

	// unload connection from strongswan
	// unloadConnReq := &goStrongswanVici.UnloadConnRequest{
	// 	Name: "test-connection",
	// }
	// err = client.UnloadConn(unloadConnReq)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("\n\n found %d connections. \n", len(connInfo))
	// fmt.Printf("connInfo: %+v\n", connInfo)
	// kill all conns in strongswan
	// for _, info := range connList {
	// 	fmt.Printf("kill connection id %s\n", info.Uniqueid)

	// err = client.Terminate(&goStrongswanVici.TerminateRequest{
	// 	Child:    "",
	// 	Ike:      "",
	// 	Child_id: "",
	// 	Ike_id:   "1",
	// 	Force:    "TRUE",
	// 	Timeout:  "-1",
	// 	Loglevel: "",
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// }

	// <-time.After(1*time.Minute)
	// connInfo, err = client.ListAllVpnConnInfo()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("found %d connections. \n", len(connInfo))
	// fmt.Printf("connInfo: %+v \n", connInfo)
}
