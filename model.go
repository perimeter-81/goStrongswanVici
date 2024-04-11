package goStrongswanVici

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

type IKEConf struct {
	LocalAddrs    []string               `json:"local_addrs"`
	RemoteAddrs   []string               `json:"remote_addrs,omitempty"`
	LocalPort     string                 `json:"local_port,omitempty"`
	RemotePort    string                 `json:"remote_port,omitempty"`
	Proposals     []string               `json:"proposals,omitempty"`
	Vips          []string               `json:"vips,omitempty"`
	Version       string                 `json:"version"` // 1 for ikev1, 0 for ikev1 & ikev2
	Encap         bool                   `json:"encap"`   // yes,no
	KeyingTries   string                 `json:"keyingtries"`
	RekeyTime     string                 `json:"rekey_time"`
	DPDDelay      string                 `json:"dpd_delay,omitempty"`
	DPDTimeout    string                 `json:"dpd_timeout,omitempty"`
	LocalAuth     AuthConf               `json:"local"`
	RemoteAuth    AuthConf               `json:"remote"`
	Pools         []string               `json:"pools,omitempty"`
	Children      map[string]ChildSAConf `json:"children"`
	Mobike        bool                   `json:"mobike,omitempty"`
	Aggressive    bool                   `json:"aggressive,omitempty"`
	Send_certreq  bool                   `json:"send_certreq,omitempty"`
	Pull          bool                   `json:"pull,omitempty"`
	If_id_in      string                 `json:"If_id_in,omitempty"`
	If_id_out     string                 `json:"If_id_out,omitempty"`
	Dscp          string                 `json:"dscp,omitempty"`
	Rand_time     string                 `json:"rand_time,omitempty"`
	Over_time     string                 `json:"over_time,omitempty"`
	Reauth_time   string                 `json:"reauth_time,omitempty"`
	Fragmentation bool                   `json:"fragmentation,omitempty"`
}

func (I *IKEConf) UnmarshalJSON(bytes []byte) error {

	// Unmarshal the JSON into a map
	var rawIkeConfMap map[string]any
	err := json.Unmarshal(bytes, &rawIkeConfMap)
	if err != nil {
		return fmt.Errorf("error unmarshalling IKEConf to raw map: %w", err)
	}

	// Unmarshal the localAuth and remoteAuth into AuthConf
	for key, value := range rawIkeConfMap {
		switch true {
		case strings.Compare(key, "version") == 0:
			I.Version = value.(string)
		case strings.Compare(key, "encap") == 0:
			I.Encap = value.(bool)
		case strings.Compare(key, "keyingtries") == 0:
			I.KeyingTries = value.(string)
		case strings.Compare(key, "rekey_time") == 0:
			I.RekeyTime = value.(string)
		case strings.Compare(key, "dpd_delay") == 0:
			I.DPDDelay = value.(string)
		case strings.Compare(key, "dpd_timeout") == 0:
			I.DPDTimeout = value.(string)
		case strings.Compare(key, "local_addrs") == 0:
			rawLocalAddrs, ok := value.([]interface{})
			if !ok {
				return fmt.Errorf("error unmarshalling localAddrs to raw map: %w", err)
			}

			I.LocalAddrs = make([]string, len(rawLocalAddrs))
			for i, v := range rawLocalAddrs {
				I.LocalAddrs[i] = fmt.Sprint(v)
			}
		case strings.Compare(key, "remote_addrs") == 0:
			rawRemoteAddrs, ok := value.([]interface{})
			if !ok {
				return fmt.Errorf("error unmarshalling remoteAddrs to raw map: %w", err)
			}
			I.RemoteAddrs = make([]string, len(rawRemoteAddrs))
			for i, v := range rawRemoteAddrs {
				I.RemoteAddrs[i] = fmt.Sprint(v)
			}
		case strings.Compare(key, "local_port") == 0:
			I.LocalPort = value.(string)
		case strings.Compare(key, "remote_port") == 0:
			I.RemotePort = value.(string)
		case strings.Compare(key, "proposals") == 0:
			I.Proposals = value.([]string)
		case strings.Compare(key, "vips") == 0:
			I.Vips = value.([]string)
		case strings.Compare(key, "aggresive") == 0:
			I.Aggressive = value.(bool)
		case strings.Compare(key, "send_certreq") == 0:
			I.Send_certreq = value.(bool)
		case strings.Compare(key, "pull") == 0:
			I.Pull = value.(bool)
		case strings.Compare(key, "if_id_in") == 0:
			I.If_id_in = value.(string)
		case strings.Compare(key, "if_id_out") == 0:
			I.If_id_out = value.(string)
		case strings.Compare(key, "dscp") == 0:
			I.Dscp = value.(string)
		case strings.Compare(key, "rand_time") == 0:
			I.Rand_time = value.(string)
		case strings.Compare(key, "over_time") == 0:
			I.Over_time = value.(string)
		case strings.Compare(key, "reauth_time") == 0:
			I.Reauth_time = value.(string)
		case strings.Compare(key, "fragmentation") == 0:
			I.Fragmentation = value.(bool)
		case strings.Compare(key, "children") == 0:
			rawChildSAConf, ok := value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("error unmarshalling childSAConf to raw map: %w", err)
			}

			childSAConf := make(map[string]ChildSAConf)
			for childID, childSA := range rawChildSAConf {
				conf := ChildSAConf{}

				err := ConvertFromGeneral(childSA, &conf)
				if err != nil {
					return err
				}

				childSAConf[childID] = conf
			}

			I.Children = childSAConf
		case strings.HasPrefix(key, "local"):
			rawLocalAuth, ok := value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("error unmarshalling localAuth to raw map: %w", err)
			}

			newLocalAuth := AuthConf{}
			err := ConvertFromGeneral(rawLocalAuth, &newLocalAuth)
			if err != nil {
				return err
			}

			I.LocalAuth = newLocalAuth
		case strings.HasPrefix(key, "remote"):
			rawRemoteAuth, ok := value.(map[string]interface{})
			if !ok {
				return fmt.Errorf("error unmarshalling remoteAuth to raw map: %w", err)
			}

			newRemoteAuth := AuthConf{}
			err := ConvertFromGeneral(rawRemoteAuth, &newRemoteAuth)
			if err != nil {
				return err
			}

			I.RemoteAuth = newRemoteAuth

		default:
			// return fmt.Errorf("unknown key in IKEConf: %s",x key)
		}
	}

	return nil
}

type ChildSAConf struct {
	LocalTs       []string `json:"local_ts"`
	RemoteTs      []string `json:"remote_ts"`
	ESPProposals  []string `json:"esp_proposals,omitempty"` // aes128-sha1_modp1024
	StartAction   string   `json:"start_action"`            // none,trap,start
	CloseAction   string   `json:"close_action"`
	ReqID         string   `json:"reqid,omitempty"`
	RekeyTime     string   `json:"rekey_time"`
	ReplayWindow  string   `json:"replay_window,omitempty"`
	Mode          string   `json:"mode"` // "tunnel", "transport", "beet", "drop", "pass"
	InstallPolicy string   `json:"policies"`
	UpDown        string   `json:"updown,omitempty"`
	Priority      string   `json:"priority,omitempty"`
	MarkIn        string   `json:"mark_in,omitempty"`
	MarkOut       string   `json:"mark_out,omitempty"`
	DpdAction     string   `json:"dpd_action,omitempty"`
	LifeTime      string   `json:"life_time,omitempty"`
}

func (c *ChildSAConf) UnmarshalJSON(bytes []byte) error {

	rawChildSAConfMap := map[string]any{}
	err := json.Unmarshal(bytes, &rawChildSAConfMap)
	if err != nil {
		return fmt.Errorf("error unmarshalling ChildSAConf to raw map: %w", err)
	}

	for key, value := range rawChildSAConfMap {
		switch key {
		case "local_ts", "local-ts":
			rawLocalTs, ok := value.([]interface{})
			if !ok {
				return fmt.Errorf("error unmarshalling localTs to raw map: %+v", value)
			}

			c.LocalTs = make([]string, len(rawLocalTs))
			for i, v := range rawLocalTs {
				c.LocalTs[i] = fmt.Sprint(v)
			}
		case "remote_ts", "remote-ts":
			rawRemoteTs, ok := value.([]interface{})
			if !ok {
				return fmt.Errorf("error unmarshalling remoteTs to raw map: %+v", value)
			}

			c.RemoteTs = make([]string, len(rawRemoteTs))
			for i, v := range rawRemoteTs {
				c.RemoteTs[i] = fmt.Sprint(v)
			}
		case "esp_proposals", "esp-proposals":
			c.ESPProposals = value.([]string)
		case "start_action", "start-action":
			c.StartAction = value.(string)
		case "close_action", "close-action":
			c.CloseAction = value.(string)
		case "reqid":
			c.ReqID = value.(string)
		case "rekey_time", "rekey-time":
			c.RekeyTime = value.(string)
		case "replay_window", "replay-window":
			c.ReplayWindow = value.(string)
		case "mode":
			c.Mode = value.(string)
		case "policies":
			c.InstallPolicy = value.(string)
		case "updown":
			c.UpDown = value.(string)
		case "priority":
			c.Priority = value.(string)
		case "mark_in", "mark-in":
			c.MarkIn = value.(string)
		case "mark_out", "mark-out":
			c.MarkOut = value.(string)
		case "dpd_action", "dpd-action":
			c.DpdAction = value.(string)
		case "life_time", "life-time":
			c.LifeTime = value.(string)
		}
	}

	return nil
}

type AuthConf struct {
	ID         string   `json:"id"`
	Round      int      `json:"round,omitempty"`
	AuthMethod string   `json:"auth"` // (psk|pubkey)
	EAP_ID     string   `json:"eap_id,omitempty"`
	PubKeys    []string `json:"pubkeys,omitempty"` // PEM encoded public keys
}

// SetPublicKeys is a helper method that converts Public Keys to x509 PKIX PEM format
// Supported formats are those implemented by x509.MarshalPKIXPublicKey
func (a *AuthConf) SetPublicKeys(keys []crypto.PublicKey) error {
	var newKeys []string

	for _, key := range keys {
		asn1Bytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return fmt.Errorf("Error marshaling key: %v", err)
		}
		pemKey := pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		}
		pemBytes := pem.EncodeToMemory(&pemKey)
		newKeys = append(newKeys, string(pemBytes))
	}

	a.PubKeys = newKeys
	return nil
}
