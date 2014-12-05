package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/coreos/go-log/log"
	"github.com/docker/docker/api"
	"github.com/docker/libtrust"
	"github.com/docker/libtrust/trustgraph"
)

func main() {
	dir := path.Join(getHomeDir(), ".docker")
	app := cli.NewApp()
	app.Name = "trust"
	app.Usage = "manage keys and grants"
	app.Commands = []cli.Command{
		cli.Command{
			Name:   "grant",
			Usage:  "create grant",
			Action: actionGrant,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "subject,s",
					Value: "",
					Usage: "Subject namespace of grant",
				},
				cli.StringFlag{
					Name:  "grantee,g",
					Value: "",
					Usage: "Grantee of grant",
				},
				cli.BoolFlag{
					Name:  "local",
					Usage: "Whether to use the local ID as the subject",
				},
			},
		},
		cli.Command{
			Name:   "register",
			Usage:  "register a key to a namespace",
			Action: actionRegister,
		},
		cli.Command{
			Name:   "grants",
			Usage:  "list grants",
			Action: actionGrants,
		},
	}
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "dir,d",
			Value: dir,
			Usage: "Directory for keys",
		},
		cli.StringFlag{
			Name:  "grants",
			Value: path.Join(dir, "grants"),
			Usage: "Directory for grants",
		},
	}

	app.Run(os.Args)
}

func getHomeDir() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("USERPROFILE")
	}
	return os.Getenv("HOME")
}

func LoadOrCreateTrustKey(trustKeyPath string) (libtrust.PrivateKey, error) {
	err := os.MkdirAll(path.Dir(trustKeyPath), 0700)
	if err != nil {
		return nil, err
	}
	trustKey, err := libtrust.LoadKeyFile(trustKeyPath)
	if err == libtrust.ErrKeyFileDoesNotExist {
		trustKey, err = libtrust.GenerateECP256PrivateKey()
		if err != nil {
			return nil, fmt.Errorf("Error generating key: %s", err)
		}
		if err := libtrust.SaveKey(trustKeyPath, trustKey); err != nil {
			return nil, fmt.Errorf("Error saving key file: %s", err)
		}
		dir, file := path.Split(trustKeyPath)
		// Save public key
		if err := libtrust.SavePublicKey(path.Join(dir, "public-"+file), trustKey.PublicKey()); err != nil {
			return nil, fmt.Errorf("Error saving public key file: %s", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("Error loading key file: %s", err)
	}
	return trustKey, nil
}

func actionGrant(c *cli.Context) {
	verbs := []string{c.Args().First()}
	if len(verbs) == 0 {
		cli.ShowCommandHelp(c, "grant")
		return
	}

	k, err := api.LoadOrCreateTrustKey(path.Join(c.GlobalString("dir"), "key.json"))
	if err != nil {
		log.Errorf("Error loading key file: %s", err)
		return
	}

	var subject string
	if c.Bool("local") {
		subject = k.KeyID()
	} else {
		subject = c.String("subject")
	}

	grantee := c.String("grantee")
	log.Infof("%s %s #%v", grantee, subject, verbs)

	if grantee == "" || subject == "" {
		cli.ShowCommandHelp(c, "grant")
		return
	}

	grant, err := trustgraph.NewGrant(subject, grantee, verbs)
	if err != nil {
		log.Errorf("Error creating grant")
		return
	}

	if err := grant.Sign(k); err != nil {
		log.Errorf("Error signing grant: %s", err)
		return
	}

	b, err := grant.JWS()
	if err != nil {
		log.Errorf("Error creating JWS: %s", err)
		return
	}

	log.Infof("Grant:\n%s\n", b)

	// Store grant
	filename := path.Join(c.GlobalString("grants"), subject+"-"+grantee+".json")
	err = ioutil.WriteFile(filename, b, os.FileMode(0644))
	if err != nil {
		log.Errorf("unable to write grant file %s: %s", filename, err)
		return
	}

	// Push grant
	if _, err := http.Post("http://localhost:8048/grants/", "application/json", bytes.NewReader(b)); err != nil {
		log.Errorf("unable to post grant to trust server: %s", err)
		return
	}
}

func actionRegister(c *cli.Context) {
	subject := c.Args().First()
	if subject == "" {
		cli.ShowCommandHelp(c, "register")
		return
	}

	k, err := LoadOrCreateTrustKey(path.Join(c.GlobalString("dir"), "key.json"))
	if err != nil {
		log.Errorf("error loading key: %s", err)
	}

	b, err := k.PublicKey().MarshalJSON()
	if err != nil {
		log.Errorf("error marshalling public key: %s", err)
	}

	// Make request to trust server
	r, err := http.Post("http://localhost:8048/register/"+subject, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Errorf("error sending data: %s", err)
	}

	gBytes, err := ioutil.ReadAll(r.Body)
	filename := path.Join(c.GlobalString("grants"), "register-"+subject+".json")
	err = ioutil.WriteFile(filename, gBytes, os.FileMode(0644))
	if err != nil {
		log.Errorf("unable to write grant file %s: %s", filename, err)
	}
}

func actionGrants(c *cli.Context) {
	files, err := ioutil.ReadDir(c.GlobalString("grants"))
	if err != nil {
		log.Errorf("error reading grants directory: %s", err)
	}

	for _, f := range files {
		if !f.IsDir() {
			b, err := ioutil.ReadFile(path.Join(c.GlobalString("grants"), f.Name()))
			if err != nil {
				log.Errorf("error reading grant file: %s", err)
			}

			g, err := trustgraph.LoadGrant(b)
			if err != nil {
				// TODO: don't throw an error here
				log.Errorf("error loading grant: %s", err)
			}

			keys, err := g.Verify()
			if err != nil {
				// TODO: don't throw an error here
				log.Errorf("error verifying grant: %s", err)
			}
			for _, key := range keys {
				fmt.Printf("%s: %s -> %s %s\n", key.KeyID(), g.Subject, g.Grantee, strings.Join(g.Scopes, ","))
			}
		}
	}
}
