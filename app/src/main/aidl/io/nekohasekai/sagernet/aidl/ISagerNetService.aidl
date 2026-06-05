package io.nekohasekai.sagernet.aidl;

import io.nekohasekai.sagernet.aidl.ISagerNetServiceCallback;

interface ISagerNetService {
  int getState();
  String getProfileName();
  long getSmartRuntimeGroupId();
  long getSmartActiveProxyId();
  long getSmartStandbyProxyId();
  int getSmartSessionHealth();
  long getSmartTxRate();
  long getSmartRxRate();
  String getSmartLastDecision();
  String getSmartQuarantinedProxyIds();

  void registerCallback(in ISagerNetServiceCallback cb, int id);
  oneway void unregisterCallback(in ISagerNetServiceCallback cb);

  int urlTest();
}
