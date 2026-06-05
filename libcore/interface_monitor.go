package libcore

import (
	"sync"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
)

type interfaceMonitorStub struct {
	lock        sync.Mutex
	callbacks   list.List[tun.DefaultInterfaceUpdateCallback]
	myInterface string
	closed      bool
}

var (
	activeInterfaceMonitor     *interfaceMonitorStub
	activeInterfaceMonitorLock sync.Mutex
)

func (s *interfaceMonitorStub) Start() error {
	s.lock.Lock()
	s.closed = false
	activeInterfaceMonitorLock.Lock()
	activeInterfaceMonitor = s
	activeInterfaceMonitorLock.Unlock()
	s.lock.Unlock()
	return nil
}

func (s *interfaceMonitorStub) Close() error {
	s.lock.Lock()
	s.closed = true
	activeInterfaceMonitorLock.Lock()
	if activeInterfaceMonitor == s {
		activeInterfaceMonitor = nil
	}
	activeInterfaceMonitorLock.Unlock()
	s.lock.Unlock()
	return nil
}

func (s *interfaceMonitorStub) DefaultInterface() *control.Interface {
	return nil
}

func (s *interfaceMonitorStub) OverrideAndroidVPN() bool {
	return false
}

func (s *interfaceMonitorStub) AndroidVPNEnabled() bool {
	return false
}

func (s *interfaceMonitorStub) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *interfaceMonitorStub) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	if element == nil {
		return
	}
	s.lock.Lock()
	s.callbacks.Remove(element)
	s.lock.Unlock()
}

func (s *interfaceMonitorStub) RegisterMyInterface(interfaceName string) {
	s.lock.Lock()
	s.myInterface = interfaceName
	s.lock.Unlock()
}

func (s *interfaceMonitorStub) MyInterface() string {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.myInterface
}

func (s *interfaceMonitorStub) notifyNetworkChanged() {
	s.lock.Lock()
	if s.closed {
		s.lock.Unlock()
		return
	}
	callbacks := make([]tun.DefaultInterfaceUpdateCallback, 0, s.callbacks.Len())
	for element := s.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	s.lock.Unlock()
	for _, callback := range callbacks {
		callback(nil, 0)
	}
}

// NotifyNetworkChanged invalidates network-scoped health and wakes sing-box listeners.
func NotifyNetworkChanged() {
	healthManager.syncNetworkScope(time.Now().UnixMilli())
	activeInterfaceMonitorLock.Lock()
	monitor := activeInterfaceMonitor
	activeInterfaceMonitorLock.Unlock()
	if monitor != nil {
		monitor.notifyNetworkChanged()
	}
}
