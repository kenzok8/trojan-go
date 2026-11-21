package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kenzok8/trojan-go/common"
	"github.com/kenzok8/trojan-go/config"
	"github.com/kenzok8/trojan-go/statistic/memory"
)

func TestServerAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = config.WithConfig(ctx, memory.Name,
		&memory.Config{
			Passwords: []string{},
		})
	port := common.PickPort("tcp", "127.0.0.1")
	ctx = config.WithConfig(ctx, Name, &Config{
		APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
		},
	})
	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go RunServerAPI(ctx, auth)
	time.Sleep(time.Second * 3)
	common.Must(auth.AddUser("hash1234"))
	_, user := auth.AuthUser("hash1234")
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	common.Must(err)
	server := NewTrojanServerServiceClient(conn)
	stream1, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	for {
		resp, err := stream1.Recv()
		if err != nil {
			break
		}
		fmt.Println(resp.Status.User.Hash)
		if resp.Status.User.Hash != "hash1234" {
			t.Fail()
		}
		fmt.Println(resp.Status.SpeedCurrent)
		fmt.Println(resp.Status.SpeedLimit)
	}
	stream1.CloseSend()
	user.AddTraffic(1234, 5678)
	time.Sleep(time.Second * 1)
	stream2, err := server.GetUsers(ctx)
	common.Must(err)
	stream2.Send(&GetUsersRequest{
		User: &User{
			Hash: "hash1234",
		},
	})
	resp2, err := stream2.Recv()
	common.Must(err)
	if resp2.Status.TrafficTotal.DownloadTraffic != 1234 || resp2.Status.TrafficTotal.UploadTraffic != 5678 {
		t.Fatal("wrong traffic")
	}

	stream3, err := server.SetUsers(ctx)
	common.Must(err)
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: "hash1234",
			},
		},
		Operation: SetUsersRequest_Delete,
	})
	resp3, err := stream3.Recv()
	if err != nil || !resp3.Success {
		t.Fatal("user not exists")
	}
	valid, _ := auth.AuthUser("hash1234")
	if valid {
		t.Fatal("failed to auth")
	}
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: "newhash",
			},
		},
		Operation: SetUsersRequest_Add,
	})
	resp3, err = stream3.Recv()
	if err != nil || !resp3.Success {
		t.Fatal("failed to read")
	}
	valid, user = auth.AuthUser("newhash")
	if !valid {
		t.Fatal("failed to auth 2")
	}
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: "newhash",
			},
			SpeedLimit: &Speed{
				DownloadSpeed: 5000,
				UploadSpeed:   3000,
			},
			TrafficTotal: &Traffic{
				DownloadTraffic: 1,
				UploadTraffic:   1,
			},
		},
		Operation: SetUsersRequest_Modify,
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			user.AddTraffic(200, 0)
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			user.AddTraffic(0, 300)
		}
	}()
	time.Sleep(time.Second * 3)
	for i := 0; i < 3; i++ {
		stream2.Send(&GetUsersRequest{
			User: &User{
				Hash: "newhash",
			},
		})
		resp2, err = stream2.Recv()
		common.Must(err)
		fmt.Println(resp2.Status.SpeedCurrent)
		fmt.Println(resp2.Status.SpeedLimit)
		time.Sleep(time.Second)
	}
	stream2.CloseSend()
	cancel()
}

func TestTLSRSA(t *testing.T) {
	port := common.PickPort("tcp", "127.0.0.1")
	cfg := &Config{
		API: APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
			SSL: SSLConfig{
				Enabled:        true,
				CertPath:       "server-rsa2048.crt",
				KeyPath:        "server-rsa2048.key",
				VerifyClient:   false,
				ClientCertPath: []string{"client-rsa2048.crt"},
			},
		},
	}

	ctx := config.WithConfig(context.Background(), Name, cfg)
	ctx = config.WithConfig(ctx, memory.Name,
		&memory.Config{
			Passwords: []string{},
		})

	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go func() {
		common.Must(RunServerAPI(ctx, auth))
	}()
	time.Sleep(time.Second)
	pool := x509.NewCertPool()
	certBytes, err := os.ReadFile("server-rsa2048.crt")
	common.Must(err)
	pool.AppendCertsFromPEM(certBytes)

	certificate, err := tls.LoadX509KeyPair("client-rsa2048.crt", "client-rsa2048.key")
	common.Must(err)
	creds := credentials.NewTLS(&tls.Config{
		ServerName:   "localhost",
		RootCAs:      pool,
		Certificates: []tls.Certificate{certificate},
	})
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(creds))
	common.Must(err)
	server := NewTrojanServerServiceClient(conn)
	stream, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	stream.CloseSend()
	conn.Close()
}

func TestTLSECC(t *testing.T) {
	port := common.PickPort("tcp", "127.0.0.1")
	cfg := &Config{
		API: APIConfig{
			Enabled: true,
			APIHost: "127.0.0.1",
			APIPort: port,
			SSL: SSLConfig{
				Enabled:        true,
				CertPath:       "server-ecc.crt",
				KeyPath:        "server-ecc.key",
				VerifyClient:   false,
				ClientCertPath: []string{"client-ecc.crt"},
			},
		},
	}

	ctx := config.WithConfig(context.Background(), Name, cfg)
	ctx = config.WithConfig(ctx, memory.Name,
		&memory.Config{
			Passwords: []string{},
		})

	auth, err := memory.NewAuthenticator(ctx)
	common.Must(err)
	go func() {
		common.Must(RunServerAPI(ctx, auth))
	}()
	time.Sleep(time.Second)
	pool := x509.NewCertPool()
	certBytes, err := os.ReadFile("server-ecc.crt")
	common.Must(err)
	pool.AppendCertsFromPEM(certBytes)

	certificate, err := tls.LoadX509KeyPair("client-ecc.crt", "client-ecc.key")
	common.Must(err)
	creds := credentials.NewTLS(&tls.Config{
		ServerName:   "localhost",
		RootCAs:      pool,
		Certificates: []tls.Certificate{certificate},
	})
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(creds))
	common.Must(err)
	server := NewTrojanServerServiceClient(conn)
	stream, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	stream.CloseSend()
	conn.Close()
}

var serverRSA2048Cert = `-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIUHtSppSsfXR3U0drhaQAtNQhq8YowDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTEyMTExMTI0NFoXDTM2MTEx
ODExMTI0NFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEArtu6kny2YczeyFD/s3vfSPOlGxd02IHGr8nHHyP68HcB
zG4/luNdBmpLphHlbm+t8uV6C2rUT+aZojce3RF8iXN6/TgO5r09aYhAkPzTWcQ+
Sdt+AItcOH6livax+DyZSHcuMa2vHIf6eZtONaDuJZIqiGZnydQNxf3guWjkXGJs
wDPw6wDA6ZS54IeM/dezBlgcTL444/crRkSInLR/lPpleT05Zi483hVAonHWqtz0
rNm1I8fCpV2QZSJqx72048Dhoy63O3Ru2BbuHtSu8boLVz9GvUHF2JirURD7LKmc
CXJOhVBI1ujrvPPAZCTgZ6u4iQ6Ak4t2ig38eOFscwIDAQABo4GMMIGJMB0GA1Ud
DgQWBBS9VAO5k8waz1xYz2J+jjHWveViBDAfBgNVHSMEGDAWgBS9VAO5k8waz1xY
z2J+jjHWveViBDAPBgNVHRMBAf8EBTADAQH/MBQGA1UdEQQNMAuCCWxvY2FsaG9z
dDALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQEL
BQADggEBAF4/ZiIuHvoxRHTRJeymGdfRoBDIwrf/POZJ16i2XEbh8D7qb4Pof8RP
3UEW77yBdvXsCfu0Ff7RWiqqKpCeywwH9yvfOWx/mspAtm78BRrhZC0pbuTKg4BE
QPk54CMwSy8LCwyVPyWkexStL+8OkihW428OIX1dnFuYJX1Sh8HUuwUEKqKFSncm
TTa6burt8a+GXrZu0aPcoMIUlo51zN2chuaZVzPrl0cV0e8yX8aX9AhWzrf+Yo97
0XFlylLk82Ah7eY3irIfePfg4JIcsJscembKWmwlrUhQVqtY4EJoqnwLtEOipr/9
MUXclAMFnet3aVFMxeVmUgRm0p8acLs=
-----END CERTIFICATE-----
`

var serverRSA2048Key = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu27qSfLZhzN7I
UP+ze99I86UbF3TYgcavyccfI/rwdwHMbj+W410GakumEeVub63y5XoLatRP5pmi
Nx7dEXyJc3r9OA7mvT1piECQ/NNZxD5J234Ai1w4fqWK9rH4PJlIdy4xra8ch/p5
m041oO4lkiqIZmfJ1A3F/eC5aORcYmzAM/DrAMDplLngh4z917MGWBxMvjjj9ytG
RIictH+U+mV5PTlmLjzeFUCicdaq3PSs2bUjx8KlXZBlImrHvbTjwOGjLrc7dG7Y
Fu4e1K7xugtXP0a9QcXYmKtREPssqZwJck6FUEjW6Ou888BkJOBnq7iJDoCTi3aK
Dfx44WxzAgMBAAECggEBAKYhib/H0ZhWB4yWuHqUxG4RXtrAjHlvw5Acy5zgmHiC
+Sh7ztrTJf0EXN9pvWwRm1ldgXj7hMBtPaaLbD1pccM9/qo66p17Sq/LjlyyeTOe
affOHIbz4Sij2zCOdkR9fr0EztTQScF3yBhl4Aa/4cO8fcCeWxm86WEldq9x4xWJ
s5WMR4CnrOJhDINLNPQPKX92KyxEQ/RfuBWovx3M0nl3fcUWfESY134t5g/UBFId
In19tZ+pGIpCkxP0U1AZWrlZRA8Q/3sO2orUpoAOdCrGk/DcCTMh0c1pMzbYZ1/i
cYXn38MpUo8QeG4FElUhAv6kzeBIl2tRBMVzIigo+AECgYEA3No1rHdFu6Ox9vC8
E93PTZevYVcL5J5yx6x7khCaOLKKuRXpjOX/h3Ll+hlN2DVAg5Jli/JVGCco4GeK
kbFLSyxG1+E63JbgsVpaEOgvFT3bHHSPSRJDnIU+WkcNQ2u4Ky5ahZzbNdV+4fj2
NO2iMgkm7hoJANrm3IqqW8epenMCgYEAyq+qdNj5DiDzBcDvLwY+4/QmMOOgDqeh
/TzhbDRyr+m4xNT7LLS4s/3wcbkQC33zhMUI3YvOHnYq5Ze/iL/TSloj0QCp1I7L
J7sZeM1XimMBQIpCfOC7lf4tU76Fz0DTHAL+CmX1DgmRJdYO09843VsKkscC968R
4cwL5oGxxgECgYAM4TTsH/CTJtLEIfn19qOWVNhHhvoMlSkAeBCkzg8Qa2knrh12
uBsU3SCIW11s1H40rh758GICDJaXr7InGP3ZHnXrNRlnr+zeqvRBtCi6xma23B1X
F5eV0zd1sFsXqXqOGh/xVtp54z+JEinZoForLNl2XVJVGG8KQZP50kUR/QKBgH4O
8zzpFT0sUPlrHVdp0wODfZ06dPmoWJ9flfPuSsYN3tTMgcs0Owv3C+wu5UPAegxB
X1oq8W8Qn21cC8vJQmgj19LNTtLcXI3BV/5B+Aghu02gr+lq/EA1bYuAG0jjUGlD
kyx0bQzl9lhJ4b70PjGtxc2z6KyTPdPpTB143FABAoGAQDoIUdc77/IWcjzcaXeJ
8abak5rAZA7cu2g2NVfs+Km+njsB0pbTwMnV1zGoFABdaHLdqbthLWtX7WOb1PDD
MQ+kbiLw5uj8IY2HEqJhDGGEdXBqxbW7kyuIAN9Mw+mwKzkikNcFQdxgchWH1d1o
lVkr92iEX+IhIeYb4DN1vQw=
-----END PRIVATE KEY-----
`

var clientRSA2048Cert = `-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIUHhsz9tS3hhDh5LwmI9th3DxmEgEwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTEyMTExMTI0NFoXDTM2MTEx
ODExMTI0NFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAl4O7rfSWi65/ZXizDf3pwaICfGZOx5VEwb6bc+dnzfWm
4CwCmbchZIRw6ohQyTqzWmBIvKyDobFFmFfgv+WMSuMw7j7LyuJmOqpHTB3QaeG4
3G5dpJSwSYp0NltwgKpeRl5lGfiPD/svTGB0B0zbDctdHpqroLC94Vjf8mdwRkVA
cfmaeitl2luF5HquG8gvoAAjRgRj27O5AFKvM6aXd/sP7HleWXXgegw3SQLKxa3y
NI/8CfnI/ykvlE6mfmQ0FzwHHyXKS5XW5LyiCdxIzsnOak/VJ4BWI6rwKpeUm1Rt
SpU9yQyZ18wy1siog7tHn/yKat2EsyLbl8A6d+YPNwIDAQABo4GMMIGJMB0GA1Ud
DgQWBBSn0ZThQVPp/np6IxWMLYosNO43ajAfBgNVHSMEGDAWgBSn0ZThQVPp/np6
IxWMLYosNO43ajAPBgNVHRMBAf8EBTADAQH/MBQGA1UdEQQNMAuCCWxvY2FsaG9z
dDALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQEL
BQADggEBABE0WccBX2uLaj/hbqz4CdV5JRLqzKS8Wx3pVFvlnLMPzb9mF1YUZdvd
6spFmfzHVhJvm4kLOTIBdhfjrJEwHEZiWM7OlNvW2zjZKO3jPTB/kAKdtN+2H1aK
SrU6lUEhtAiK1p+pSZssTSk1j+oQAzjpL6pa+5/m9649cswGuV9oqFA4a9ZQ40IL
KH6OrEPPr3PKc9umxKy/9XP5QUvKHYtim9KcPRekrsLLnVLxrddKQt5smccRTeYy
r6116PNAYeubF7MtR6qJ7mEv6aJNz/mAiBElb/kAeDjq/I/r5YEF5qtXhv1NaD74
LBBSRMQGb/2CpHAxqCZlysGL270iQ9g=
-----END CERTIFICATE-----
`

var clientRSA2048Key = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXg7ut9JaLrn9l
eLMN/enBogJ8Zk7HlUTBvptz52fN9abgLAKZtyFkhHDqiFDJOrNaYEi8rIOhsUWY
V+C/5YxK4zDuPsvK4mY6qkdMHdBp4bjcbl2klLBJinQ2W3CAql5GXmUZ+I8P+y9M
YHQHTNsNy10emqugsL3hWN/yZ3BGRUBx+Zp6K2XaW4Xkeq4byC+gACNGBGPbs7kA
Uq8zppd3+w/seV5ZdeB6DDdJAsrFrfI0j/wJ+cj/KS+UTqZ+ZDQXPAcfJcpLldbk
vKIJ3EjOyc5qT9UngFYjqvAql5SbVG1KlT3JDJnXzDLWyKiDu0ef/Ipq3YSzItuX
wDp35g83AgMBAAECggEASOv4CjMrubKUUgwTcWqBdNY6iBDdXaVz4COSweffx/qx
BDdqUP0Yrz4m8loFN7Ru2dJ5b4VAHTQqoLW6z+D08p4B0MicYNsyBI4rnnDC/BLN
XBoqK6n8Zoiigf7kWKimkwufcS51/GUSUJojfdf5ndwAx1f9vmsSGEEkF5C9MrQo
Sa4eyySuXuDS9swrXuTn9FcVcbUoIblgL8GIlmX4S1Xl9NaVS/VAVt42FgpNSYy7
2Qf9Medg3ApimjwkLiDSh0RElirlUwzSg9dx2U+hHwWQWimb2AhA85uK3bpFB/x9
b2agS1uxTar4mk4LFppQqVUuXlpj2hW7HxTdcxGHYQKBgQDGA+Wv3b8FMeszYqqx
BbI5+FeXmQ5AoYNdHyPfCH8f2LX1FTnnQbUvFMJ3UQZl/GGHocgyFNvfDo6YyYsg
2XgcNO/JWMbKEw0HkfMgkaIa3Jfq/PTB386NhqBq5FHiBUrvSHzhaIzpuaokBrRk
jFlcqONK+uj77iRgci4wR59POQKBgQDD4fDZzOGQCy/AWrMX/adk8ymoxhWQj6PN
zhy2GZo9jGwyskQr5neIDQtxRbgokMspxpyPdQG2SxbG/zygyFEaCsp/Xb3iB3aA
2dcktkV9agx+g1WrflTpGG9quW5vQJgQv9FtlVXJdiihN9CQvXAcYRjUA/zkadIL
GsrVF9rh7wKBgFoMLaiDU7neEJKGnQ7xgzI/kD29ebDEgkOXxK1JZN4ro9t3MqTK
ycVGUIUIELvSQNv4I107BR3ztb8fcCiZHLjfDehnecctULCPm5vE/o3uoRtYu0lr
KLhNb6gMenwpYgFc2oV7ERG8v/WwItrSxFSR7QMNBWSD0IEXi4+jEnxpAoGAMJTS
5VG5B76egzh7fpG8eH8Ob/tg0c+uMpbR7CABbw5qr1AjNDgeoTGLCvbdq8HtgVju
7213lTyeU5Bt+vpzkt/mRRx8wZhUPbTJdSN3rJkmrCHql3Pnn0AeMfv3dcQxcsYA
LQuCkUqq3QE4yw0QxxkVzU+H4yaTn4lvkNYvxSUCgYEAgD85MM3DaiNcrevQv6Wb
vSo7jBhd8Q/NawH53V32eIlF9Kkm2mqTmPIQ2OxOtdZ3xm+JmPd20jEVg7NcPL58
t6BoSH10pLaI0CP2NdcYfJTIiHAhuQe7PxPCA0nlHTXgSv97QR7y4qMhbf2j1umc
hKym0tdk2QjR3qqglaD572A=
-----END PRIVATE KEY-----
`

var serverECCCert = `-----BEGIN CERTIFICATE-----
MIIBuzCCAWGgAwIBAgIUR51oWfK92SKXa8L+Ql9HZiW9J1QwCgYIKoZIzj0EAwIw
ITELMAkGA1UEBhMCQ04xEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjExMjExMTEy
NDRaFw0zNjExMTgxMTEyNDRaMCExCzAJBgNVBAYTAkNOMRIwEAYDVQQDDAlsb2Nh
bGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASvYy/r7XR1Y39lC2JpRJh5
82zR2CTNynbuolK9a1jsbXaZv+hpBlHkgzMHsWu7LY9Pnb/Dbp4i1lRASOddD/rL
o3cwdTAPBgNVHRMBAf8EBTADAQH/MBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAOBgNV
HQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1Ud
DgQWBBSmuVigC5sIT3aRWHZoDQu4xMDIsjAKBggqhkjOPQQDAgNIADBFAiAahP2U
qFJTN2OBFOUiMgAds9tasGA9Nt9M3CMGrXPbFAIhAIWvdHgwd/B/Pfa1kEFs+xfg
a5rd6h1S/V7hxJyQDt5S
-----END CERTIFICATE-----
`

var serverECCKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIB8G2suYKuBLoodNIwRMp3JPN1fcZxCt3kcOYIx4nbcPoAoGCCqGSM49
AwEHoUQDQgAEr2Mv6+10dWN/ZQtiaUSYefNs0dgkzcp27qJSvWtY7G12mb/oaQZR
5IMzB7Fruy2PT52/w26eItZUQEjnXQ/6yw==
-----END EC PRIVATE KEY-----
`

var clientECCCert = `-----BEGIN CERTIFICATE-----
MIIBuzCCAWGgAwIBAgIUCSPh/aq+gjbLVHCLlZ1Nl8f0a3AwCgYIKoZIzj0EAwIw
ITELMAkGA1UEBhMCQ04xEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjExMjExMTEy
NDRaFw0zNjExMTgxMTEyNDRaMCExCzAJBgNVBAYTAkNOMRIwEAYDVQQDDAlsb2Nh
bGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQME+DnYtcKlbcZmc33oEto
eRWH61DYdl4ei/bM+vkv01MkBB+YTZl0yofJIFJYsfU5pMFK+uywD4qdcklKPGIK
o3cwdTAPBgNVHRMBAf8EBTADAQH/MBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAOBgNV
HQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1Ud
DgQWBBRaSw1DfMlzpBFqiRGIDBaYcZi2djAKBggqhkjOPQQDAgNIADBFAiEA35on
j7KemU7y4uIHGqF2Ujp1cL9mGPeMy6zvB9Ams0ACIDv1a1xayhku7xHlhpTJYPyY
DulUi65uGqeZMkTGLlr5
-----END CERTIFICATE-----
`

var clientECCKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINgbap6WOGXm8V+ghIyporGcGWnggbjjP9xNsxhn+0sqoAoGCCqGSM49
AwEHoUQDQgAEDBPg52LXCpW3GZnN96BLaHkVh+tQ2HZeHov2zPr5L9NTJAQfmE2Z
dMqHySBSWLH1OaTBSvrssA+KnXJJSjxiCg==
-----END EC PRIVATE KEY-----
`

func init() {
	os.WriteFile("server-rsa2048.crt", []byte(serverRSA2048Cert), 0o777)
	os.WriteFile("server-rsa2048.key", []byte(serverRSA2048Key), 0o777)
	os.WriteFile("client-rsa2048.crt", []byte(clientRSA2048Cert), 0o777)
	os.WriteFile("client-rsa2048.key", []byte(clientRSA2048Key), 0o777)

	os.WriteFile("server-ecc.crt", []byte(serverECCCert), 0o777)
	os.WriteFile("server-ecc.key", []byte(serverECCKey), 0o777)
	os.WriteFile("client-ecc.crt", []byte(clientECCCert), 0o777)
	os.WriteFile("client-ecc.key", []byte(clientECCKey), 0o777)
}
