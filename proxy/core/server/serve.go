package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

var (
	transportMap = sync.Map{}
	bufferPool   = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
)

func Serve() {

	defer pnc.PanicHndl()

	if domains.Config.Proxy.Cloudflare {

		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}

		http2.ConfigureServer(service, &http2.Server{})
		service.SetKeepAlivesEnabled(true)
		service.Handler = http.HandlerFunc(Middleware)

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	} else {

		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}
		serviceH := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":443",
			TLSConfig: &tls.Config{
				GetConfigForClient: firewall.Fingerprint,
				GetCertificate:     domains.GetCertificate,
				Renegotiation:      tls.RenegotiateOnceAsClient,
			},
			MaxHeaderBytes: 1 << 20,
		}

		http2.ConfigureServer(service, &http2.Server{})
		http2.ConfigureServer(serviceH, &http2.Server{})

		service.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			firewall.Mutex.RLock()
			domainData, domainFound := domains.DomainsData[r.Host]
			firewall.Mutex.RUnlock()

			if !domainFound {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "balooProxy: "+r.Host+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
				return
			}

			firewall.Mutex.Lock()
			domainData = domains.DomainsData[r.Host]
			domainData.TotalRequests++
			domains.DomainsData[r.Host] = domainData
			firewall.Mutex.Unlock()

			http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently)
		})

		service.SetKeepAlivesEnabled(true)
		serviceH.Handler = http.HandlerFunc(Middleware)

		go func() {
			defer pnc.PanicHndl()
			if err := serviceH.ListenAndServeTLS("", ""); err != nil {
				panic(err)
			}
		}()

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	}
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer bufferPool.Put(buffer)
	transport := getTripperForDomain(req.Host)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		errStrs := strings.Split(err.Error(), " ")
		errMsg := ""
		for _, str := range errStrs {
			if !strings.Contains(str, ".") && !strings.Contains(str, "/") && !(strings.Contains(str, "[") && strings.Contains(str, "]")) {
				errMsg += str + " "
			}
		}
		html := `
		<!DOCTYPE html>
		<html lang="en">
		<head>
		  <meta charset="UTF-8" />
		  <title>Complete the CAPTCHA</title>
		  <style>
		    body { background-color:#f5f5f5; font-family:Arial,sans-serif; }
		    .center { display:flex; align-items:center; justify-content:center; height:100vh; }
		    .box { background-color:#fff; border:1px solid #ddd; border-radius:4px; padding:20px; width:500px; }
		    canvas { display:block; margin:0 auto; max-width:100%; width:100%; height:auto; }
		    input[type=text], button { width:100%; margin:8px 0; }
		    input[type=text] { padding:12px 20px; box-sizing:border-box; border:2px solid #ccc; border-radius:4px; }
		    button { background:#4caf50; color:#fff; padding:14px 20px; border:none; border-radius:4px; cursor:pointer; }
		    button:hover { background-color:#45a049; }
		    .success, .failure { display:none; padding:20px; margin-top:10px; border-radius:4px; }
		    .success { background:#dff0d8; color:#3c763d; }
		    .failure { background:#f0d8d8; color:#763c3c; }
		  </style>
		</head>
		<body>
		  <div class="center">
		    <div class="box" id="box">
		      <h1>Verify You're Human</h1>
		      <p>Slide the bar and enter the green text from the image.</p>
		      <div class="captcha-wrapper">
		        <canvas id="captcha" height="37" width="100"></canvas>
		        <canvas id="mask" height="37" width="100"></canvas>
		      </div>
		      <input id="captcha-slider" type="range" min="-50" max="50" />
		      <form onsubmit="return checkAnswer(event)">
		        <input id="text" type="text" maxlength="6" placeholder="Enter solution" />
		        <button type="submit">Submit</button>
		      </form>
		      <div class="success" id="successMessage">Success! Redirecting...</div>
		      <div class="failure" id="failMessage">Failed. Please try again.</div>
		    </div>
		  </div>
		  <script>
		    const ip = "%s";
		    const publicPart = "%s";
		    const captchaData = "%s";
		    const maskData = "%s";
			
		    const captchaImg = new Image();
		    const maskImg = new Image();
		    const canvas = document.getElementById("captcha");
		    const ctx = canvas.getContext("2d");
		    const maskCanvas = document.getElementById("mask");
		    const maskCtx = maskCanvas.getContext("2d");
			
		    captchaImg.onload = () => ctx.drawImage(captchaImg, 0, 0);
		    captchaImg.src = "data:image/png;base64," + captchaData;
			
		    maskImg.onload = () => maskCtx.drawImage(maskImg, 0, 0);
		    maskImg.src = "data:image/png;base64," + maskData;
			
		    function checkAnswer(e) {
		      e.preventDefault();
		      const val = document.getElementById("text").value;
		      document.cookie = ip + "_3_zux_v=" + val + publicPart + "; path=/; SameSite=Lax; Secure";
		      fetch("/zux/verified").then(res => res.text()).then(text => {
		        if (text === "verified") {
		          document.getElementById("successMessage").style.display = "block";
		          setTimeout(() => location.reload(), 1000);
		        } else {
		          document.getElementById("failMessage").style.display = "block";
		          setTimeout(() => location.reload(), 1000);
		        }
		      });
		    }
		  </script>
		</body>
		</html>`
		buffer.WriteString(html)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
		}, nil
	}

	if resp.StatusCode > 499 && resp.StatusCode < 600 {

		limitReader := io.LimitReader(resp.Body, 1024*1024)
		errBody, errErr := io.ReadAll(limitReader)

		resp.Body.Close()

		errMsg := ""
		if errErr == nil && len(errBody) > 0 {
			errMsg = string(errBody)
			if int64(len(errBody)) == 1024*1024 {
				errMsg += `<p>( Error message truncated. )</p>`
			}
		}

		if errErr == nil && len(errBody) != 0 {

			buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>Error:`)
			buffer.WriteString(`</h1><p>Sorry, the backend returned this error.</p><iframe width="100%" height="25%" style="border:1px ridge lightgrey; border-radius: 5px;"srcdoc="`)
			buffer.WriteString(errMsg)
			buffer.WriteString(`"></iframe><a onclick="location.reload()">Reload page</a></div></div></body></html>`)

		} else {

			buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>`)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</h1><p>Sorry, the backend returned an error. That's all we know.</p><a onclick="location.reload()">Reload page</a></div></div></body></html>`)
		}

		resp.Body.Close()

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
		}, nil
	}

	return resp, nil
}

var defaultTransport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, addr)
	},
	TLSHandshakeTimeout: 10 * time.Second,
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	IdleConnTimeout:     90 * time.Second,
	MaxIdleConns:        10,
	MaxConnsPerHost:     10,
}

func getTripperForDomain(domain string) *http.Transport {

	transport, ok := transportMap.Load(domain)
	if !ok {
		transport, _ = transportMap.LoadOrStore(domain, defaultTransport)
	}
	return transport.(*http.Transport)
}

type RoundTripper struct {
}
