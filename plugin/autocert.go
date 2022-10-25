/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package plugin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/drk1wi/Modlishka/config"
	"github.com/drk1wi/Modlishka/log"
)

// Paste your CA certificate and key in the following format
// Ref: https://github.com/drk1wi/Modlishka/wiki/Quickstart-tutorial

const CA_CERT = `-----BEGIN CERTIFICATE-----
MIIECzCCAvOgAwIBAgIUUHm/Mjvczn3gWbOjVdLzxgQHZ6EwDQYJKoZIhvcNAQEL
BQAwgZQxCzAJBgNVBAYTAk5HMQwwCgYDVQQIDANpbW8xDzANBgNVBAcMBm93ZXJy
aTESMBAGA1UECgwJZmlyZXNoYXJrMREwDwYDVQQLDAh0dXRvcmlhbDEVMBMGA1UE
AwwMZmlyZXNoYXJrLmluMSgwJgYJKoZIhvcNAQkBFhlub3JlcGx5c3VwcG9yaHRA
Z21haWwuY29tMB4XDTIyMTAyNTEzMzkyN1oXDTI1MDgxNDEzMzkyN1owgZQxCzAJ
BgNVBAYTAk5HMQwwCgYDVQQIDANpbW8xDzANBgNVBAcMBm93ZXJyaTESMBAGA1UE
CgwJZmlyZXNoYXJrMREwDwYDVQQLDAh0dXRvcmlhbDEVMBMGA1UEAwwMZmlyZXNo
YXJrLmluMSgwJgYJKoZIhvcNAQkBFhlub3JlcGx5c3VwcG9yaHRAZ21haWwuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuelEqOsyBepoN3J2OqO+
UVv4EwlLdjqzFNDSemEyXghURd13ylO1331Sx5qyJFa5eDyCfbVotCKr4xWH/M/O
vr8wZM5HGF80HFItuy6H5nbskw05zfxWoPlYYblSpePszC6I/J5kEFILsGrHtwYy
XoZBT2gEd4fZt60RTBL45bTTiGiJE6wQha6dOrpYwRj/UmOVcdWLFmN+f4WQB/r+
2FKKtw7Y/fZvW3oDapfkvYIqHLCVGzpPWQdGxxkYnPqxAiIn0N7PoaKl68NjrdaB
rMSac7PbwGWKPrR7zXTTkUgcHfEdejF8MLjPaVThvoW+CaTbo/ZGjy9YzgWf/39N
AwIDAQABo1MwUTAdBgNVHQ4EFgQUHh/Yt/ItIMHUbnmcWUKQUIrW2MEwHwYDVR0j
BBgwFoAUHh/Yt/ItIMHUbnmcWUKQUIrW2MEwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEAOc5vfx/h9WfHIQcXsM5V5HKdS3Kq4bRpVo4aWUBnmKFm
/fP4g0Gp3tUV9XwGBO393QXY099+jLC4PcSxCC1KK8T82xfYcwfAvCbjIZ9518dz
PbGMerMeyi0+IRvdvO1atcmnZB0sdVO24FK5BQgfdD0oukGHodWKZSCtrmBsXRAg
adygMHY/JxIibHUIt51v+98C5aZdWEHYusHlfjAV5PLdKvwpVg/cY2x/0bGRjfZG
XN+7TPu9xEnMN+P+k96SyHYNzpR81g0tjSmxXuhOQ+9CNpR96hvyT/VXZSXvL47o
tpFnZXtT6SapassXdC9ziyMPHfLwdaEbElTf+/iX5w==
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC56USo6zIF6mg3
cnY6o75RW/gTCUt2OrMU0NJ6YTJeCFRF3XfKU7XffVLHmrIkVrl4PIJ9tWi0Iqvj
FYf8z86+vzBkzkcYXzQcUi27LofmduyTDTnN/Fag+VhhuVKl4+zMLoj8nmQQUguw
ase3BjJehkFPaAR3h9m3rRFMEvjltNOIaIkTrBCFrp06uljBGP9SY5Vx1YsWY35/
hZAH+v7YUoq3Dtj99m9begNql+S9giocsJUbOk9ZB0bHGRic+rECIifQ3s+hoqXr
w2Ot1oGsxJpzs9vAZYo+tHvNdNORSBwd8R16MXwwuM9pVOG+hb4JpNuj9kaPL1jO
BZ//f00DAgMBAAECggEAMLccY7sFp6Et3+Ghc2o207Dqx2o3GOr2xCyYCrNvdE5w
bsJCwoS+8qovR9iUd4s2HHiWpQQlRJaVPfMFaEy32ynUL4YSASPpTsaF7zeZKt3c
zge4Lu7BcHsGGs1qB8g646IKCVAj3lbxcy/311DLYBOEB5+1E/FILqYuEyYhjGcs
WPyEnMapNTOB1E5LadbzaeA0m8P6Ifi3Dxp3RvlK2NG3CI5Pt3ldik/8+PGuOy4J
DobM7ubCOZ9f/H/L5oUNaRRxbijsRRW8fnfc3QwvKodPuxDpEThudTeskT7aHIxk
szwRcvk1NKg0LDk2Rxys2Tb23S/FLfJp+lxdkTWG8QKBgQDQsJ+uF7ovJ+C01QhI
zD9kn/Aym6r+tlCajoxw9V9HdRnMMUDLwv/A1dkm+QoWfSYl6mn3u0G3pCdyZXwJ
+V28CBKJBXZ0jLRsULdr4Y6QM8K5t+2J1e++DfPPcvR1m6HOl4W6CjsfXSTAJu8h
RU/KYzxC23joFQCid2J3ko4q2wKBgQDkDqyzq3E7bCJi0TvSvuzvX0J/l8VrgX9x
j8ko1I5sACfMChXmYrRrWvTQUzkdnnbQ3OAEX2TviJssWaBj8qbAgHNuRx3X9Wbj
uQE3CQqvy9L9uONXl/EZZk/b/3UXiEiQKltHTpcl7PG1bDTKFXAmVfzJjpiN3wkD
ZY3i8yY6+QKBgQDOlChdAyvQhh8PolnDBjwydYgl8KaB4SNE+5rWLm6Uo7xXvuGv
UmYtEwMUay2rOVNL8RHYosrY6GwL952jme9JtIv0iy3JDYeEORp4dhzTbglyIjnH
WbkqX1FbpyWKTfcMND2x/XKtB1zbwS6xtpTXeQgr/mlfA3tPV/Jm/vIwRQKBgH1M
TricPicevzm5qXudaIIPvXJqyY3KZWHYVPY46lMONs9Uzzl4C5ZcL9txjhTm5nLU
l8PvQX6VeGQCjiu7usBTEpiJPC1V6AS/tZouPo/dlXvPJCERGucQnlnJ3eRi/TMw
AlyIImU07Iv3+nz5EFgPsEZxMQHpg4M5PZ5uZxfJAoGBAM3zgda7mkEVQ/nMcsHU
hL9FJX42bGApDV5tmdMenMoN84MKhbyDJwREuF0wEs1JasCtOvVbfpDBnw79bpKe
bWscBuNyrxosgQOMTkdyH7GEpil+YQyH1letkmosR6NK1H0FAxugyWWfoKg+65Te
VrRTbNSUipQLb14neHkYwWAx
-----END PRIVATE KEY-----`

func init() {

	s := Property{}

	s.Name = "autocert"
	s.Version = "0.1"
	s.Description = "This plugin is used to auto generate certificate for you . Really useful for testing different configuration flags against your targets. "

	s.Flags = func() {

		if *config.C.ForceHTTP == false {
			if len(*config.C.TLSCertificate) == 0 && len(*config.C.TLSKey) == 0 {

				log.Infof("Autocert plugin: Auto-generating %s domain TLS certificate",*config.C.ProxyDomain)

				CAcert := CA_CERT
				CAkey := CA_CERT_KEY

				catls, err := tls.X509KeyPair([]byte(CAcert), []byte(CAkey))
				if err != nil {
					panic(err)
				}
				ca, err := x509.ParseCertificate(catls.Certificate[0])
				if err != nil {
					panic(err)
				}

				var n int32
				binary.Read(rand.Reader, binary.LittleEndian, &n)

				template := &x509.Certificate{
					IsCA:                  false,
					BasicConstraintsValid: true,
					SubjectKeyId:          []byte{1, 2, 3},
					SerialNumber:          big.NewInt(int64(n)),
					DNSNames:              []string{*config.C.ProxyDomain, "*." + *config.C.ProxyDomain},
					Subject: pkix.Name{
						Country:      []string{"Earth"},
						Organization: []string{"Mother Nature"},
						CommonName:   *config.C.ProxyDomain,
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(1, 0, 0),
				}

				// generate private key
				privatekey, err := rsa.GenerateKey(rand.Reader, 2048)

				if err != nil {
					log.Errorf("Error generating key: %s", err)
				}
				var privateKey = &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
				}

				//dump
				buf := new(bytes.Buffer)
				pem.Encode(buf, privateKey)
				tlskeyStr := buf.String()
				config.C.TLSKey = &tlskeyStr
				log.Debugf("AutoCert plugin generated TlsKey:\n %s", *config.C.TLSKey)

				// generate self signed cert
				publickey := &privatekey.PublicKey

				// create a self-signed certificate. template = parent
				//var parent = template
				var parent = ca

				cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, catls.PrivateKey)

				buf = new(bytes.Buffer)
				pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

				tlscertStr := buf.String()
				config.C.TLSCertificate = &tlscertStr
				log.Debugf("AutoCert plugin generated TlsCert:\n %s", *config.C.TLSCertificate)

				//the cert is auto-generated anyway
				*config.C.TLSPool = ""

				if err != nil {
					log.Errorf("Error creating certificate: %s", err)
				}

			}
		}

	}

	// Register all the function hooks
	s.Register()
}
