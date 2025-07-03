package firewall

import (
	"net"
	"net/http"
	"sync"
)

var (
	Mutex = &sync.RWMutex{}

	UnkFps = map[string]int{}

	WindowUnkFps = map[int]map[string]int{}

	AccessIps = map[string]int{}

	WindowAccessIps = map[int]map[string]int{}

	AccessIpsCookie       = map[string]int{}
	WindowAccessIpsCookie = map[int]map[string]int{}

	CacheIps = sync.Map{}

	CacheImgs = sync.Map{}

	Connections = map[string]string{}
)

func OnStateChange(conn net.Conn, state http.ConnState) {

	remoteAddr := conn.RemoteAddr().String()

	switch state {
	case http.StateNew:
	case http.StateHijacked, http.StateClosed:
		Mutex.Lock()
		delete(Connections, remoteAddr)
		Mutex.Unlock()
	}
}
