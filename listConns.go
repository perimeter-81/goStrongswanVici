package goStrongswanVici

import (
	"fmt"
)

func (c *ClientConn) ListConns(ike string) (conns []map[string]IKEConf, err error) {
	conns = []map[string]IKEConf{}
	var eventErr error

	defer func() {
		errUnregister := c.UnregisterEvent("list-conn")
		if errUnregister != nil {
			if err != nil {
				err = fmt.Errorf("error unregistering list-conns event: %v. original error: %w", errUnregister, err)
				return
			}
			err = fmt.Errorf("error unregistering list-conns event: %w", errUnregister)
		}
	}()

	err = c.RegisterEvent("list-conn", func(response map[string]interface{}) {
		conn := &map[string]IKEConf{}
		err = ConvertFromGeneral(response, conn)
		if err != nil {
			eventErr = fmt.Errorf("list-conn event error: %w", err)

			return
		}
		conns = append(conns, *conn)
	})

	if err != nil {
		return nil, fmt.Errorf("error registering list-conn event: %v", err)
	}

	if eventErr != nil {
		return nil, eventErr
	}

	reqMap := map[string]interface{}{}

	if ike != "" {
		reqMap["ike"] = ike
	}

	_, err = c.Request("list-conns", reqMap)
	if err != nil {
		return nil, fmt.Errorf("error requesting list-conns: %v", err)
	}

	return conns, nil
}
