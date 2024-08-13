package jwtutils

import (
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"io"
	"log"
	"net/http"

	wasmer "github.com/wasmerio/wasmer-go/wasmer"
)

type AuthenticateResponse struct {
	ServerTime      int64  `json:"serverTime"`
	Salt            string `json:"salt"`
	AccessToken     string `json:"accessToken"`
	TokenType       string `json:"tokenType"`
	RefreshToken    string `json:"refreshToken"`
	Salt1           int32  `json:"salt1"`
	Salt2           int32  `json:"salt2"`
	Salt3           int32  `json:"salt3"`
	Salt4           int32  `json:"salt4"`
	Salt5           int32  `json:"salt5"`
	IsDisplayActive bool   `json:"isDisplayActive"`
	PopupDocFor     string `json:"popupDocFor"`
}

//go:embed nepsejwtutils.wasm
var wasmBytes []byte

var cdx *wasmer.Function
var rdx *wasmer.Function
var bdx *wasmer.Function
var ndx *wasmer.Function
var mdx *wasmer.Function

func init() {

	engine := wasmer.NewEngine()
	store := wasmer.NewStore(engine)

	// Compiles the module
	module, err := wasmer.NewModule(store, wasmBytes)

	if err != nil {
		log.Fatal(err)
	}
	// Instantiates the module
	importObject := wasmer.NewImportObject()
	instance, err := wasmer.NewInstance(module, importObject)
	if err != nil {
		log.Fatal(err)
	}

	cdx, err = instance.Exports.GetRawFunction("cdx")
	if err != nil {
		log.Fatal(err)
	}
	rdx, err = instance.Exports.GetRawFunction("rdx")
	if err != nil {
		log.Fatal(err)
	}
	bdx, err = instance.Exports.GetRawFunction("bdx")
	if err != nil {
		log.Fatal(err)
	}
	ndx, err = instance.Exports.GetRawFunction("ndx")

	if err != nil {
		log.Fatal(err)
	}
	mdx, err = instance.Exports.GetRawFunction("mdx")

	if err != nil {
		log.Fatal(err)
	}
}

func Cdx(val1, val2, val3, val4, val5 int32) (int32, error) {
	return callDXFn(cdx, val1, val2, val3, val4, val5)
}

func Rdx(val1, val2, val3, val4, val5 int32) (int32, error) {
	return callDXFn(rdx, val1, val2, val3, val4, val5)
}

func Bdx(val1, val2, val3, val4, val5 int32) (int32, error) {
	return callDXFn(bdx, val1, val2, val3, val4, val5)
}

func Ndx(val1, val2, val3, val4, val5 int32) (int32, error) {
	return callDXFn(ndx, val1, val2, val3, val4, val5)
}

func Mdx(val1, val2, val3, val4, val5 int32) (int32, error) {
	return callDXFn(mdx, val1, val2, val3, val4, val5)
}

func callDXFn(fn *wasmer.Function, p1, p2, p3, p4, p5 int32) (int32, error) {
	val, err := fn.Call(p1, p2, p3, p4, p5)

	if err != nil {
		return 0, err
	}

	if ok := val.(int32); ok == 0 {
		return 0, err
	}

	return val.(int32), err
}

func (a *AuthenticateResponse) GetParsedAccessToken() (string, error) {

	i1, err := Cdx(a.Salt1, a.Salt2, a.Salt3, a.Salt4, a.Salt5)
	if err != nil {
		return "", err
	}

	i2, err := Rdx(a.Salt1, a.Salt2, a.Salt4, a.Salt3, a.Salt5)
	if err != nil {
		return "", err
	}

	i3, err := Bdx(a.Salt1, a.Salt2, a.Salt4, a.Salt3, a.Salt5)
	if err != nil {
		return "", err
	}

	i4, err := Ndx(a.Salt1, a.Salt2, a.Salt4, a.Salt3, a.Salt5)
	if err != nil {
		return "", err
	}

	i5, err := Mdx(a.Salt1, a.Salt2, a.Salt4, a.Salt3, a.Salt5)
	if err != nil {
		return "", err
	}

	final := a.AccessToken[0:i1] + a.AccessToken[i1+1:i2] + a.AccessToken[i2+1:i3] + a.AccessToken[i3+1:i4] + a.AccessToken[i4+1:i5] + a.AccessToken[i5+1:]

	return final, nil
}

func (a *AuthenticateResponse) GetParsedRefreshToken() (string, error) {

	i1, err := Cdx(a.Salt2, a.Salt1, a.Salt3, a.Salt5, a.Salt4)
	if err != nil {
		return "", err
	}

	i2, err := Rdx(a.Salt2, a.Salt1, a.Salt3, a.Salt4, a.Salt5)
	if err != nil {
		return "", err
	}

	i3, err := Bdx(a.Salt2, a.Salt1, a.Salt4, a.Salt3, a.Salt5)
	if err != nil {
		return "", err
	}

	i4, err := Ndx(a.Salt2, a.Salt1, a.Salt4, a.Salt3, a.Salt5)
	if err != nil {
		return "", err
	}

	i5, err := Mdx(a.Salt2, a.Salt1, a.Salt4, a.Salt3, a.Salt5)
	if err != nil {
		return "", err
	}

	final := a.RefreshToken[0:i1] + a.RefreshToken[i1+1:i2] + a.RefreshToken[i2+1:i3] + a.RefreshToken[i3+1:i4] + a.RefreshToken[i4+1:i5] + a.RefreshToken[i5+1:]

	return final, nil
}

func Authenticate() (*AuthenticateResponse, error) {
	url := "https://www.nepalstock.com/api/authenticate/prove"

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0")
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")
	req.Header.Add("Accept-Encoding", "gzip, deflate, br")
	req.Header.Add("Connection", "close")
	req.Header.Add("Referer", "")
	req.Header.Add("Pragma", "no-cache")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("TE", "Trailers")

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	reader, err := gzip.NewReader(res.Body)

	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(reader)

	if err != nil {
		return nil, err
	}

	var authenticateResponse AuthenticateResponse

	err = json.Unmarshal(body, &authenticateResponse)

	return &authenticateResponse, err
}
