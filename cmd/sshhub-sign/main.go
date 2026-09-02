// Command sshhub-sign produces the signed release manifest.
//
// It runs on the MAINTAINER's machine (or in a release job holding the signing
// key), never on a hub or an agent. The private key must not be present
// anywhere that a hub, an agent, or a workflow with release-publish rights can
// read it: the whole point is that publishing a release and signing one require
// different secrets.
//
//	sshhub-sign keygen                       generate a signing keypair
//	sshhub-sign manifest --version 0.5.0 --dir dist [--urgent "reason"]
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Trickhish/sshhub/internal/release"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		keygen()
	case "manifest":
		manifest(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("Usage: sshhub-sign <command>")
	fmt.Println()
	fmt.Println("  keygen                          Generate an Ed25519 release signing keypair")
	fmt.Println("  manifest --version <v> --dir <d> [--urgent <reason>] [--out <file>]")
	fmt.Println("                                  Build and sign a release manifest")
	fmt.Println()
	fmt.Println("The private key is read from SSHHUB_SIGNING_KEY (base64) or --key <file>.")
}

func keygen() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	fmt.Println("Release signing keypair generated.")
	fmt.Println()
	fmt.Println("PRIVATE KEY (keep offline; never place on a hub, an agent, or in a")
	fmt.Println("workflow that can publish releases):")
	fmt.Printf("  %s\n", base64.StdEncoding.EncodeToString(priv))
	fmt.Println()
	fmt.Println("PUBLIC KEY (compile into binaries via ldflags):")
	fmt.Printf("  %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Println()
	fmt.Println("Build with:")
	fmt.Printf("  -ldflags \"-X github.com/Trickhish/sshhub/internal/release.TrustedPublicKey=%s \\\n",
		base64.StdEncoding.EncodeToString(pub))
	fmt.Println("            -X github.com/Trickhish/sshhub/internal/release.RequireSignature=true\"")
}

func manifest(args []string) {
	var version, dir, urgent, keyFile, out string
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			log.Fatalf("%s requires a value", args[i])
			return ""
		}
		switch args[i] {
		case "--version":
			version = next()
		case "--dir":
			dir = next()
		case "--urgent":
			urgent = next()
		case "--key":
			keyFile = next()
		case "--out":
			out = next()
		}
	}

	if version == "" || dir == "" {
		log.Fatal("--version and --dir are required")
	}
	version = strings.TrimPrefix(version, "v")

	priv, err := loadPrivateKey(keyFile)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Fatalf("read %s: %v", dir, err)
	}

	artifacts := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		digest, err := sha256File(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Fatalf("hash %s: %v", e.Name(), err)
		}
		artifacts[e.Name()] = digest
	}
	if len(artifacts) == 0 {
		log.Fatalf("no .tar.gz artifacts found in %s", dir)
	}

	m := &release.Manifest{
		SchemaVersion: release.ManifestVersion,
		Version:       version,
		PublishedAt:   time.Now().UTC().Truncate(time.Second),
		Artifacts:     artifacts,
		Urgent:        urgent != "",
		UrgentReason:  urgent,
	}

	sm, err := release.Sign(m, priv)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	data, err := json.MarshalIndent(sm, "", "  ")
	if err != nil {
		log.Fatalf("encode: %v", err)
	}

	if out == "" {
		out = filepath.Join(dir, "sshhub-manifest.json")
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", out, err)
	}

	fmt.Printf("Signed manifest written to %s\n", out)
	for _, n := range m.ArtifactNames() {
		fmt.Printf("  %s  %s\n", artifacts[n], n)
	}
	if m.Urgent {
		fmt.Printf("\nMarked URGENT: %s\n", m.UrgentReason)
		fmt.Println("Hubs will install this release immediately, bypassing auto_update_wait.")
	}
}

func loadPrivateKey(file string) (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(os.Getenv("SSHHUB_SIGNING_KEY"))
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return nil, fmt.Errorf("set SSHHUB_SIGNING_KEY or pass --key <file>")
	}

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("key must be base64 or hex")
		}
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", ed25519.PrivateKeySize, len(decoded))
	}
	return ed25519.PrivateKey(decoded), nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
