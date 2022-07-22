package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mokumoku-lovers/moku-moku-oauth-go/oauth/errors"

	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic     = "X-Public"
	headerAccessToken = "access_token"
)

var oauthRestClient = rest.RequestBuilder{
	BaseURL: "http://168.138.215.26:9001",
	Timeout: 10 * time.Second,
}

type accessToken struct {
	Id     string `json:"id"`
	UserId int64  `json:"user_id"`
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return errors.InternalServerError("No request provided to authenticate")
	}

	accessTokenId := strings.TrimSpace(request.Header.Get(headerAccessToken))
	if accessTokenId == "" {
		return errors.BadRequest("No token provided")
	}

	_, err := getAccessToken(accessTokenId)
	if err != nil {
		return err
	}
	return nil
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	if response.StatusCode == http.StatusNotFound {
		return nil, errors.BadRequest("Invalid token")
	}

	if response == nil || response.Response == nil {
		return nil, errors.InternalServerError("invalid restclient response when attempting to get access token")
	}
	if response.StatusCode > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, errors.InternalServerError("invalid error interface when trying to get access token")
		}
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.InternalServerError("error when trying to unmarshal access token response")
	}
	return &at, nil
}
