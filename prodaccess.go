package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	url "github.com/baffinbay/go-openurl"
	pb "github.com/baffinbay/proto/auth"
	"github.com/google/uuid"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	grpcService   = flag.String("grpc", "PLACEHOLDER_CHANGE_ME", "Authentication server to use")
	tlsServerName = flag.String("server_name", "PLACEHOLDER_CHANGE_ME", "TLS server name to verify")
	useTLS        = flag.Bool("tls", true, "Whether or not to use TLS for the GRPC connection")
	webURL        = flag.String("web", "https://PLACEHOLDER_CHANGE_ME", "Domain to reply to ident requests from")
	// TODO(bluecmd): This should be automatic
	requestBrowser = flag.Bool("browser", false, "Whether or not to request a browser certificate")
	ident          = ""
)

func presentIdent(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain")
	w.Header().Add("Access-Control-Allow-Origin", *webURL)
	w.Write([]byte(ident))
}

func quit(w http.ResponseWriter, r *http.Request) {
	// This is used to kill any other prodaccess that is lingering, enforcing
	// that only one is running.
	log.Printf("Got termination request by /quit")
	os.Exit(0)
}

func mustServeHttp() {
	err := http.ListenAndServe(":1215", nil)
	if err != nil {
		log.Fatalf("could not serve backend http: %v", err)
	}
}

func generateEcdsaCsr() (string, string, error) {
	keyb, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	asnKey, err := x509.MarshalECPrivateKey(keyb)
	if err != nil {
		return "", "", err
	}
	keyPemBlob := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: asnKey})

	subj := pkix.Name{
		CommonName: "replaced-by-the-server",
	}
	tmpl := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrb, _ := x509.CreateCertificateRequest(rand.Reader, &tmpl, keyb)
	pemBlob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrb})

	return string(keyPemBlob), string(pemBlob), nil
}

func main() {
	flag.Parse()

	// Attempt to kill any already running prodaccess
	http.Get("http://localhost:1215/quit")

	// Create ident server, used to validate requests to protect from crosslinking.
	ident = uuid.New().String()
	http.HandleFunc("/", presentIdent)
	http.HandleFunc("/quit", quit)
	go mustServeHttp()

	d := grpc.WithInsecure()
	if *useTLS {
		d = grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{
				ServerName: *tlsServerName,
			}),
		)
	}

	conn, err := grpc.Dial(*grpcService, d)
	if err != nil {
		log.Printf("could not connect: %v", err)
		conn = nil
	}

	defer conn.Close()
	c := pb.NewAuthenticationServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ucr := &pb.UserCredentialRequest{
		ClientValidation: &pb.ClientValidation{
			Ident: ident,
		},
	}

	browserPk := ""
	if *requestBrowser {
		csr := ""
		log.Printf("Generating Browser CSR ...")
		browserPk, csr, err = generateEcdsaCsr()
		if err != nil {
			log.Fatalf("failed to generate Browser CSR: %v", err)
		}
		ucr.BrowserCertificateRequest = &pb.BrowserCertificateRequest{
			Csr: csr,
		}
	}

	sshPkey, err := sshGetPublicKey()
	if err == nil {
		ucr.SshCertificateRequest = &pb.SshCertificateRequest{
			PublicKey: sshPkey,
		}
	}

	log.Printf("Sending credential request")
	stream, err := c.RequestUserCredential(ctx, ucr)
	if err != nil {
		log.Fatalf("could not request credentials: %v", err)
	}

	response, err := stream.Recv()
	for {
		if err != nil {
			log.Printf("Error: %v", err)
			return
		}
		if response.RequiredAction != nil {
			log.Printf("Required action: %v", response.RequiredAction)
			url.Open(*webURL + response.RequiredAction.Url)
		} else {
			break
		}
		response, err = stream.Recv()
	}

	if response.SshCertificate != nil {
		sshLoadCertificate(response.SshCertificate.Certificate)
	}

	if response.BrowserCertificate != nil {
		full := append([]string{response.BrowserCertificate.Certificate}, response.BrowserCertificate.CaChain...)
		saveBrowserCertificate(strings.Join(full, "\n"), browserPk)
	}
}
