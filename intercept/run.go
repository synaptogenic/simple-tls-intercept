package intercept

import (
	"fmt"
	"os"

	"github.com/synaptogenic/simple-tls-intercept/cert"
	"github.com/synaptogenic/simple-tls-intercept/hosts"
	"github.com/synaptogenic/simple-tls-intercept/proxy"
)

func Run() {
	var err error
	defer func() {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()

	domains, err := getDomains()
	if err != nil {
		return
	}

	var certManager cert.Manager

	err = certManager.InstallCA()
	if err != nil {
		return
	}
	defer certManager.UntrustCA()

	var hostsManager hosts.Manager
	err = hostsManager.Intercept(domains)
	if err != nil {
		return
	}
	defer hostsManager.Clear()

	certs, err := certManager.GenerateCerts(domains)
	if err != nil {
		return
	}

	var proxy proxy.Proxy
	err = proxy.Start(certs)
}
