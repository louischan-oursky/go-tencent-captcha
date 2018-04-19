package tencentcaptcha

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

const DefaultVerificationServerURL = "https://ssl.captcha.qq.com/ticket/verify"

type VerificationError string

const (
	ErrCmdNoMatch          VerificationError = "cmd no match"
	ErrUserCodeLenError                      = "user code len error"
	ErrUinNoMatch                            = "uin no match"
	ErrCaptchaNoMatch                        = "captcha no match"
	ErrSeqRedirect                           = "seq redirect"
	ErrVerifyTimeout                         = "verify timeout"
	ErrOptNoVcode                            = "opt no vcode"
	ErrSequnceRepeat                         = "Sequnce repeat"
	ErrDiff                                  = "diff"
	ErrSequnceInvalid                        = "Sequnce invalid"
	ErrCaptchaTypeNotMatch                   = "captcha type not match"
	ErrCookieInvalid                         = "Cookie invalid"
	ErrVerifyTypeError                       = "verify type error"
	ErrVerifyIpNoMatch                       = "verify ip no match"
	ErrInvalidPkg                            = "invalid pkg"
	ErrDecryptFail                           = "decrypt fail"
	ErrBadVisitor                            = "bad visitor"
	ErrAppidNoMatch                          = "appid no match"
	ErrSystemBusy                            = "system busy"
)

type TencentCaptcha struct {
	AppID                 string
	AppSecretKey          string
	VerificationServerURL string
}

type Ticket struct {
	Ticket  string
	Randstr string
	UserIP  string
}

type Result struct {
	Success   bool
	EvilLevel int
	Error     VerificationError
}

type responseBody struct {
	Response  string `json:"response"`
	EvilLevel string `json:"evil_level"`
	ErrMsg    string `json:"err_msg"`
}

func (c *TencentCaptcha) Verify(ticket Ticket) (result Result, err error) {
	// Build the form
	form := url.Values{}
	form.Add("aid", c.AppID)
	form.Add("AppSecretKey", c.AppSecretKey)
	form.Add("Ticket", ticket.Ticket)
	form.Add("Randstr", ticket.Randstr)
	form.Add("UserIP", ticket.UserIP)

	// Request
	endpoint := DefaultVerificationServerURL
	if c.VerificationServerURL != "" {
		endpoint = c.VerificationServerURL
	}
	resp, err := http.PostForm(endpoint, form)
	if err != nil {
		return
	}
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	responseBody := responseBody{}
	err = json.Unmarshal(bytes, &responseBody)
	if err != nil {
		return
	}

	// Parse responseBody
	responseInt, err := strconv.ParseInt(responseBody.Response, 10, 0)
	if err != nil {
		return
	}
	success := responseInt == 1

	var evilLevel int64
	if responseBody.EvilLevel != "" {
		evilLevel, err = strconv.ParseInt(responseBody.EvilLevel, 10, 0)
		if err != nil {
			return
		}
	}

	verificationError := VerificationError("")
	switch VerificationError(responseBody.ErrMsg) {
	case ErrCmdNoMatch:
		verificationError = ErrCmdNoMatch
	case ErrUserCodeLenError:
		verificationError = ErrUserCodeLenError
	case ErrUinNoMatch:
		verificationError = ErrUinNoMatch
	case ErrCaptchaNoMatch:
		verificationError = ErrCaptchaNoMatch
	case ErrSeqRedirect:
		verificationError = ErrSeqRedirect
	case ErrVerifyTimeout:
		verificationError = ErrVerifyTimeout
	case ErrOptNoVcode:
		verificationError = ErrOptNoVcode
	case ErrSequnceRepeat:
		verificationError = ErrSequnceRepeat
	case ErrDiff:
		verificationError = ErrDiff
	case ErrSequnceInvalid:
		verificationError = ErrSequnceInvalid
	case ErrCaptchaTypeNotMatch:
		verificationError = ErrCaptchaTypeNotMatch
	case ErrCookieInvalid:
		verificationError = ErrCookieInvalid
	case ErrVerifyTypeError:
		verificationError = ErrVerifyTypeError
	case ErrVerifyIpNoMatch:
		verificationError = ErrVerifyIpNoMatch
	case ErrInvalidPkg:
		verificationError = ErrInvalidPkg
	case ErrDecryptFail:
		verificationError = ErrDecryptFail
	case ErrBadVisitor:
		verificationError = ErrBadVisitor
	case ErrAppidNoMatch:
		verificationError = ErrAppidNoMatch
	case ErrSystemBusy:
		verificationError = ErrSystemBusy
	}

	result = Result{
		Success:   success,
		EvilLevel: int(evilLevel),
		Error:     verificationError,
	}
	err = nil
	return
}
