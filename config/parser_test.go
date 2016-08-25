package config

import "testing"

// Test parsing
func TestParsing(t *testing.T) {
	config := `Host google
  HostName google.com
  User goog
  Port 2222
  ProxyCommand ssh -q pluto nc saturn 22
  HostKeyAlgorithms ssh-dss
  # comment
  IdentityFile ~/.ssh/company

Host nit
  HostName nitmedia.com
  User root
  Port 22`

	_, err := parse(config)

	if err != nil {
		t.Errorf("unable to parse config: %s", err.Error())
	}
}
