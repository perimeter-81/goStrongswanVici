package goStrongswanVici

import (
	"fmt"
)

type Connection struct {
	ConnConf map[string]IKEConf `json:"connections"`
}

func (c *ClientConn) LoadConn(conn *map[string]IKEConf) error {
	requestMap := &map[string]interface{}{}

	err := ConvertToGeneral(conn, requestMap)

	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	msg, err := c.Request("load-conn", *requestMap)

	if msg["success"] != "yes" {
		return fmt.Errorf("unsuccessful LoadConn: %v", msg["errmsg"])
	}

	return nil
}
