// Package easyssh provides a simple implementation of some SSH protocol features in Go.
// You can simply run command on remote server or get a file even simple than native console SSH client.
// Do not need to think about Dials, sessions, defers and public keys...Let easyssh will be think about it!
package ssh

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/chonthu/ssh/config"

	"golang.org/x/crypto/ssh"
)

// Contains main authority information.
// User field should be a name of user on remote server (ex. john in ssh john@example.com).
// Server field should be a remote machine address (ex. example.com in ssh john@example.com)
// Key is a path to private key on your local machine.
// Port is SSH server port on remote machine.
// Note: easyssh looking for private key in user's home directory (ex. /home/john + Key).
// Then ensure your Key begins from '/' (ex. /.ssh/id_rsa)
type MakeConfig struct {
	User   string
	Server string
	Key    []string
	Port   string
}

// returns ssh.Signer from user you running app home path + cutted key path.
// (ex. pubkey,err := getKeyFile("/.ssh/id_rsa") )
func getKeyFile(keypath string) (ssh.Signer, error) {
	file := keypath
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	pubkey, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}

	return pubkey, nil
}

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

// connects to remote server using MakeConfig struct and returns *ssh.Session
func (ssh_conf *MakeConfig) Connect() (*ssh.Session, error) {

	hosts, err := config.ParseSSHConfig(os.Getenv("HOME") + "/.ssh/config")
	if err != nil {
		return nil, err
	}

	for _, host := range hosts {
		if stringInSlice(ssh_conf.Server, host.Host) {
			ssh_conf.Server = host.HostName
			ssh_conf.User = host.User
			ssh_conf.Port = strconv.Itoa(host.Port)
			ssh_conf.Key = []string{host.IdentityFile}
		}
	}

	var keys []ssh.Signer

	for _, v := range ssh_conf.Key {
		pubkey, err := getKeyFile(v)
		if err != nil {
			continue
		}
		keys = append(keys, pubkey)
	}

	config := &ssh.ClientConfig{
		User: ssh_conf.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(keys...),
		},
	}

	client, err := ssh.Dial("tcp", ssh_conf.Server+":"+ssh_conf.Port, config)
	if err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	return session, nil
}

// Runs command on remote machine and returns STDOUT
func (ssh_conf *MakeConfig) Run(command string) (string, error) {
	session, err := ssh_conf.Connect()

	if err != nil {
		return "", err
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run(command)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

// Scp uploads sourceFile to remote machine like native scp console app.
func (ssh_conf *MakeConfig) Scp(sourceFile string) error {
	session, err := ssh_conf.Connect()

	if err != nil {
		return err
	}
	defer session.Close()

	targetFile := filepath.Base(sourceFile)

	src, srcErr := os.Open(sourceFile)

	if srcErr != nil {
		return srcErr
	}

	srcStat, statErr := src.Stat()

	if statErr != nil {
		return statErr
	}

	go func() {
		w, _ := session.StdinPipe()

		fmt.Fprintln(w, "C0644", srcStat.Size(), targetFile)

		if srcStat.Size() > 0 {
			io.Copy(w, src)
			fmt.Fprint(w, "\x00")
			w.Close()
		} else {
			fmt.Fprint(w, "\x00")
			w.Close()
		}
	}()

	if err := session.Run(fmt.Sprintf("scp -t %s", targetFile)); err != nil {
		return err
	}

	return nil
}

// Stream returns one channel that combines the stdout and stderr of the command
// as it is run on the remote machine, and another that sends true when the
// command is done. The sessions and channels will then be closed.
func Stream(ssh_conf *MakeConfig, command string) (output chan string, done chan bool, err error) {
	// connect to remote host
	session, err := ssh_conf.Connect()
	if err != nil {
		return output, done, err
	}
	// connect to both outputs (they are of type io.Reader)
	outReader, err := session.StdoutPipe()
	if err != nil {
		return output, done, err
	}
	errReader, err := session.StderrPipe()
	if err != nil {
		return output, done, err
	}
	// combine outputs, create a line-by-line scanner
	outputReader := io.MultiReader(outReader, errReader)
	err = session.Start(command)
	scanner := bufio.NewScanner(outputReader)
	// continuously send the command's output over the channel
	outputChan := make(chan string)
	done = make(chan bool)
	go func(scanner *bufio.Scanner, out chan string, done chan bool) {
		defer close(outputChan)
		defer close(done)
		for scanner.Scan() {
			outputChan <- scanner.Text()
		}
		// close all of our open resources
		done <- true
		session.Close()
	}(scanner, outputChan, done)
	return outputChan, done, err
}
