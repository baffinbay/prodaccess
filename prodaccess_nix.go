package main

import (
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
)

var (
	sshPubKey       = flag.String("sshpubkey", "$HOME/.ssh/id_ecdsa_prodaccess.pub", "SSH public key to request signed")
	sshCert         = flag.String("sshcert", "$HOME/.ssh/id_ecdsa_prodaccess-cert.pub", "SSH certificate to write")
	sshKnownHosts   = flag.String("sshknownhosts", "$HOME/.ssh/known_hosts", "SSH known hosts file to use")
	vaultTokenPath  = flag.String("vault_token", "$HOME/.vault-token", "Path to Vault token to update")
	browserCertPath = flag.String("browser_cert_path", "$HOME/browser-user.pfx", "Path to store Browswer user certificate")

	certAuthority = "@cert-authority *.baffinbay.network ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAEoUf5ceRV9LeCzj7aGAGv6djOdpTP24LIQ/5L1n8nDi5W55Tnk9egnhB4dkNSFJVv9Atml2rhUgapmAfkhK3AqewB8VX5b8matGS68q/JXGFSKnBGB7SXiuf/XTSe2NVk/pCArtYWhiMk6tO0SySX8mVbtHkapCx2D5VeeFtT2hFJV1g=="
)

func sshLoadCertificate(c string) {
	cp := os.ExpandEnv(*sshCert)
	err := ioutil.WriteFile(cp, []byte(c), 0644)
	if err != nil {
		log.Printf("failed to write SSH certificate: %v", err)
	}

	// Add cert authority to known_hosts
	path := os.ExpandEnv(*sshKnownHosts)
	kh, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("failed to read SSH known hosts: %v", err)
	} else {
		if !strings.Contains(string(kh), certAuthority) {
			log.Printf("adding server identity to SSH known hosts")
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				log.Printf("failed to open SSH known hosts file for writing: %v", err)
			}
			defer f.Close()
			if _, err = f.WriteString(certAuthority); err != nil {
				log.Printf("failed to write to SSH known hosts file: %v", err)
			}
		} else {
			log.Printf("skipping SSH known hosts, already exists")
		}
	}

	// OpenSSH requires adding the private key again to load certificates
	pp := strings.TrimSuffix(cp, "-cert.pub")
	exec.Command("/usr/bin/env", "ssh-add", "-t", "20h", pp).Run()
}

func sshGetPublicKey() (string, error) {
	key, err := ioutil.ReadFile(os.ExpandEnv(*sshPubKey))
	if err != nil {
		log.Printf("could not read SSH public key: %v", err)
		return "", err
	}
	return string(key), nil
}

func saveVaultToken(t string) {
	tp := os.ExpandEnv(*vaultTokenPath)
	os.Remove(tp)
	err := ioutil.WriteFile(tp, []byte(t), 0400)
	if err != nil {
		log.Printf("failed to write Vault token: %v", err)
	}
}

func hasKubectl() bool {
	_, err := exec.LookPath("kubectl")
	if err != nil {
		return false
	}
	return true
}

func saveBrowserCertificate(c string, k string) {
	cf, _ := ioutil.TempFile("", "prodaccess-browser")
	kf, _ := ioutil.TempFile("", "prodaccess-browser")
	cf.Write([]byte(c))
	kf.Write([]byte(k))
	cp := cf.Name()
	kp := kf.Name()
	defer os.Remove(cp)
	defer os.Remove(kp)
	cf.Close()
	kf.Close()

	fp := os.ExpandEnv(*browserCertPath)
	os.Remove(fp)
	os.OpenFile(fp, os.O_CREATE, 0600)
	executeWithStdout("openssl", "pkcs12", "-export", "-password", "pass:", "-in", cp, "-inkey", kp, "-out", fp)
}

func executeWithStdout(cmd ...string) (string, error) {
	return executeWithStdoutWithStdin("", cmd...)
}

func executeWithStdoutWithStdin(stdin string, cmd ...string) (string, error) {
	c := exec.Command("/usr/bin/env", cmd...)
	var stdout, stderr bytes.Buffer
	si := bytes.NewBufferString(stdin)
	c.Stdout = &stdout
	c.Stderr = &stderr
	c.Stdin = si
	err := c.Run()
	if err != nil {
		log.Printf("Failed to execute %v: %v", cmd, err)
		return "", err
	}

	return stdout.String(), nil
}

func executeWithStdin(stdin string, cmd ...string) error {
	_, err := executeWithStdoutWithStdin(stdin, cmd...)
	return err
}

func urlOpen(url string) error {
	var err error
	if *forceChrome {
		err = exec.Command("/usr/bin/open", "-a", "Google Chrome", url).Run()
	} else if *forceFirefox {
		err = exec.Command("/usr/bin/open", "-a", "Firefox", url).Run()
	} else {
		err = exec.Command("/usr/bin/open", url).Run()
	}
	return err
}
