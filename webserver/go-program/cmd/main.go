package main

import (
	"bufio"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"webserver/cmd/util"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	SNAP_NAME  = "azure-iot-identity"
	APP_NAME   = "tpm2-webserver"
	HANDLE     = 0x81010004 // With handle '0x81000001' it will not work because there is already a key there
	URL_PREFIX = "/azure-iot-identity"
)

func getEnv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

// Load TPM envvars from SNAP_DATA/system-configuration/certificate-manager/tpm2/envvars
func loadTPMEnvvars() error {
	snapData := os.Getenv("SNAP_DATA")
	envFile := filepath.Join(snapData, "system-configuration/certificate-manager/tpm2/envvars")

	f, err := os.Open(envFile)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimPrefix(line, "export ")
		if eq := strings.Index(line, "="); eq > 0 {
			k := line[:eq]
			v := strings.Trim(line[eq+1:], `"'`)
			os.Setenv(k, v)
		}
	}

	return scanner.Err()
}

func certPaths() (csrPath, certPath, tpmPubPath, www, sockDir, sockPath, tpmSocket string) {
	SNAP := getEnv("SNAP", "")
	SNAP_DATA := getEnv("SNAP_DATA", "")
	SNAP_COMMON := getEnv("SNAP_COMMON", "")
	PROJECT := getEnv("SNAP_INSTANCE_NAME", "sdk-tpm2-test-pedro-webserver")
	CERTSTORE := filepath.Join(SNAP_COMMON, "package-certificates", SNAP_NAME, APP_NAME)
	csrPath = filepath.Join(CERTSTORE, "own", "certs", "webserver.csr")
	certPath = filepath.Join(CERTSTORE, "own", "certs", "webserver.crt")
	tpmPubPath = filepath.Join(CERTSTORE, "own", "private", "webserver_pub.pem")
	www = filepath.Join(SNAP, "www")
	sockDir = filepath.Join(SNAP_DATA, "package-run", PROJECT)
	sockPath = filepath.Join(sockDir, "web.sock")
	tpmSocket = filepath.Join(SNAP_DATA, "tpm2-socket", "tpm2.sock")

	return
}

func runTPM2ReadPublic(tpmPubPath string) {
	// Simulate: tpm2_readpublic -c HANDLE -f pem -o tpmPubPath
	_, _, _, _, _, _, tpmSocket := certPaths()

	rwc, err := util.OpenTPMStreamSocket(tpmSocket)
	if err != nil {
		return
	}
	defer rwc.Close()

	pub, _, _, err := tpm2.ReadPublic(rwc, tpmutil.Handle(HANDLE))
	if err != nil {
		return
	}

	key, err := pub.Key()
	if err != nil {
		return
	}

	rsaPub, ok := key.(*rsa.PublicKey)
	if !ok {
		return
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)})

	os.MkdirAll(filepath.Dir(tpmPubPath), 0755)
	os.WriteFile(tpmPubPath, pemBytes, 0644)
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	return string(b)
}

func writeFile(path string, data []byte) error {
	os.MkdirAll(filepath.Dir(path), 0755)

	return os.WriteFile(path, data, 0644)
}

func jsonResponse(w http.ResponseWriter, code int, obj interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(obj)
}

func fileResponse(w http.ResponseWriter, path, ctype string) {
	f, err := os.Open(path)
	if err != nil {
		jsonResponse(w, 404, map[string]string{"error": "not found"})
		return
	}
	defer f.Close()

	st, _ := f.Stat()

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", fmt.Sprint(st.Size()))
	io.Copy(w, f)
}

func handler(w http.ResponseWriter, r *http.Request) {
	csrPath, certPath, tpmPubPath, www, _, _, _ := certPaths()
	p := r.URL.Path
	p = strings.TrimPrefix(p, URL_PREFIX)

	if p == "" {
		p = "/"
	}

	switch {
	case p == "/" || p == "/index.html":
		fileResponse(w, filepath.Join(www, "index.html"), "text/html; charset=utf-8")
		return

	case p == "/api/csr":
		jsonResponse(w, 200, map[string]string{"pem": readFile(csrPath)})
		return

	case p == "/api/status":
		jsonResponse(w, 200, map[string]interface{}{
			"csr_present":  fileExists(csrPath),
			"cert_present": fileExists(certPath),
			"handle":       fmt.Sprintf("0x%08x", HANDLE),
		})
		return

	case p == "/api/cert":
		if r.Method == "GET" {
			if fileExists(certPath) {
				fileResponse(w, certPath, "application/x-pem-file")
			} else {
				jsonResponse(w, 404, map[string]string{"error": "no cert"})
			}
			return
		} else if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			defer r.Body.Close()

			block, _ := pem.Decode(body)
			if block == nil || block.Type != "CERTIFICATE" {
				jsonResponse(
					w, 400, map[string]interface{}{"ok": false, "error": "Invalid PEM"})
				return
			}

			if err := writeFile(certPath, body); err != nil {
				jsonResponse(w, 500, map[string]interface{}{"ok": false, "error": err.Error()})
				return
			}

			jsonResponse(w, 200, map[string]interface{}{"ok": true, "path": certPath})
			return
		}
	case p == "/api/validate":
		if !fileExists(certPath) {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "no cert uploaded"})
			return
		}

		runTPM2ReadPublic(tpmPubPath)
		tpmPub := readFile(tpmPubPath)
		certPEM := readFile(certPath)
		errors := []string{}

		// Robust PEM decode for cert
		certBlock, _ := pem.Decode([]byte(certPEM))
		if certBlock == nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "invalid certificate PEM"})
			return
		}

		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "invalid certificate: " + err.Error()})
			return
		}

		certPub, certPubOk := cert.PublicKey.(*rsa.PublicKey)
		if !certPubOk || certPub == nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "certificate public key is not RSA"})
			return
		}

		// Robust PEM decode for TPM public key
		tpmBlock, _ := pem.Decode([]byte(tpmPub))
		if tpmBlock == nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "invalid TPM public key PEM"})
			return
		}

		tpmKey, err := x509.ParsePKCS1PublicKey(tpmBlock.Bytes)
		if err != nil || tpmKey == nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "invalid TPM public key: " + err.Error()})
			return
		}

		pubMatch := certPub.N.Cmp(tpmKey.N) == 0 && certPub.E == tpmKey.E

		// Signature roundtrip
		dataFile := "/etc/hostname"
		data, _ := os.ReadFile(dataFile)

		sig, err1 := signWithTPM(data)
		if err1 != nil {
			errors = append(errors, "signWithTPM: "+err1.Error())
		}

		hash := sha256.Sum256(data)
		err2 := error(nil)
		if err1 == nil {
			err2 = rsa.VerifyPKCS1v15(certPub, crypto.SHA256, hash[:], sig)
			if err2 != nil {
				errors = append(errors, "verify: "+err2.Error())
			}
		}

		roundtrip := err1 == nil && err2 == nil
		valid := pubMatch && roundtrip

		code := 200
		if !valid {
			code = 400
		}

		jsonResponse(w, code, map[string]interface{}{
			"ok": valid, "pubkey_match": pubMatch, "sign_verify_roundtrip": roundtrip, "errors": errors,
		})

		return

	case p == "/api/gen-signed-leaf":
		// Only allow if validation is OK
		runTPM2ReadPublic(tpmPubPath)
		certPEM := readFile(certPath)
		tpmPub := readFile(tpmPubPath)

		certBlock, _ := pem.Decode([]byte(certPEM))
		if certBlock == nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "invalid certificate PEM"})
			return
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "invalid certificate: " + err.Error()})
			return
		}
		certPub, certPubOk := cert.PublicKey.(*rsa.PublicKey)
		if !certPubOk || certPub == nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "certificate public key is not RSA"})
			return
		}
		tpmBlock, _ := pem.Decode([]byte(tpmPub))
		if tpmBlock == nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "invalid TPM public key PEM"})
			return
		}
		tpmKey, err := x509.ParsePKCS1PublicKey(tpmBlock.Bytes)
		if err != nil || tpmKey == nil {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "invalid TPM public key: " + err.Error()})
			return
		}
		pubMatch := certPub.N.Cmp(tpmKey.N) == 0 && certPub.E == tpmKey.E
		dataFile := "/etc/hostname"
		data, _ := os.ReadFile(dataFile)
		sig, err1 := signWithTPM(data)
		hash := sha256.Sum256(data)
		err2 := error(nil)
		if err1 == nil {
			err2 = rsa.VerifyPKCS1v15(certPub, crypto.SHA256, hash[:], sig)
		}
		roundtrip := err1 == nil && err2 == nil
		valid := pubMatch && roundtrip
		if !valid {
			jsonResponse(w, 400, map[string]interface{}{"ok": false, "error": "validation failed, cannot generate leaf"})
			return
		}

		// Generate a random leaf key
		leafKeyPath := filepath.Join(filepath.Dir(certPath), "leaf.key")
		leafCSRPath := filepath.Join(filepath.Dir(certPath), "leaf.csr")
		leafCertPath := filepath.Join(filepath.Dir(certPath), "leaf.crt")

		leafKey, err := rsa.GenerateKey(os.Stdout, 2048)
		if err != nil {
			jsonResponse(w, 500, map[string]interface{}{"ok": false, "error": "keygen failed: " + err.Error()})
			return
		}
		keyOut, _ := os.Create(leafKeyPath)
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
		keyOut.Close()

		// Create CSR for the leaf key
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "leaf.example.com",
				Organization: []string{"Example Org"},
			},
		}
		csrDER, err := x509.CreateCertificateRequest(os.Stdout, &csrTemplate, leafKey)
		if err != nil {
			jsonResponse(w, 500, map[string]interface{}{"ok": false, "error": "csr failed: " + err.Error()})
			return
		}
		csrOut, _ := os.Create(leafCSRPath)
		pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
		csrOut.Close()

		// Use TPM key as CA signer
		_, _, _, _, _, _, tpmSocket := certPaths()
		rwc, err := util.OpenTPMStreamSocket(tpmSocket)
		if err != nil {
			jsonResponse(w, 500, map[string]interface{}{"ok": false, "error": "TPM open failed: " + err.Error()})
			return
		}
		defer rwc.Close()
		tpmCAKey, err := client.LoadCachedKey(rwc, tpmutil.Handle(HANDLE), nil)
		if err != nil {
			jsonResponse(w, 500, map[string]interface{}{"ok": false, "error": "TPM key load failed: " + err.Error()})
			return
		}
		defer tpmCAKey.Close()
		signer, err := tpmCAKey.GetSigner()
		if err != nil {
			jsonResponse(w, 500, map[string]interface{}{"ok": false, "error": "TPM signer failed: " + err.Error()})
			return
		}

		// Prepare leaf certificate template
		leafTemplate := x509.Certificate{
			SerialNumber:          cert.SerialNumber,
			Subject:               csrTemplate.Subject,
			NotBefore:             cert.NotBefore,
			NotAfter:              cert.NotAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		leafDER, err := x509.CreateCertificate(os.Stdout, &leafTemplate, cert, &leafKey.PublicKey, signer)
		if err != nil {
			jsonResponse(w, 500, map[string]interface{}{"ok": false, "error": "sign failed: " + err.Error()})
			return
		}
		certOut, _ := os.Create(leafCertPath)
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		certOut.Close()

		jsonResponse(w, 200, map[string]interface{}{
			"ok":        true,
			"leaf_key":  leafKeyPath,
			"leaf_csr":  leafCSRPath,
			"leaf_cert": leafCertPath,
		})
		return

	default:
		// Serve static files
		safe := filepath.Clean(p)
		safe = strings.TrimPrefix(safe, "/")

		full := filepath.Join(www, safe)
		if fileExists(full) {
			ctype := "application/octet-stream"

			if strings.HasSuffix(full, ".css") {
				ctype = "text/css"
			} else if strings.HasSuffix(full, ".js") {
				ctype = "application/javascript"
			}

			fileResponse(w, full, ctype)

			return
		}

		jsonResponse(w, 404, map[string]string{"error": "not found"})
	}
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func signWithTPM(data []byte) ([]byte, error) {
	_, _, _, _, _, _, tpmSocket := certPaths()

	rwc, err := util.OpenTPMStreamSocket(tpmSocket)
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	key, err := client.LoadCachedKey(rwc, tpmutil.Handle(HANDLE), nil)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	hashed := sha256.Sum256(data)
	signer, err := key.GetSigner()
	if err != nil {
		return nil, err
	}

	return signer.Sign(nil, hashed[:], crypto.SHA256)
}

func main() {
	if err := loadTPMEnvvars(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load TPM envvars: %v\n", err)
		os.Exit(1)
	}

	_, _, _, _, sockDir, sockPath, _ := certPaths()
	os.MkdirAll(sockDir, 0777)

	if _, err := os.Stat(sockPath); err == nil {
		os.Remove(sockPath)
	}

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		panic(err)
	}

	os.Chmod(sockPath, 0666)

	fmt.Printf("[web-ui] listening on unix:%s\n", sockPath)

	http.HandleFunc("/", handler)
	http.Serve(l, nil)
}
