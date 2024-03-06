package oauthserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func getGoogleUserData(accessToken string) (oauthUser, error) {
	response, err := http.Get(
		fmt.Sprintf("https://www.googleapis.com/oauth2/v3/userinfo?access_token=%s", accessToken),
	)
	if err != nil {
		return oauthUser{}, fmt.Errorf("error in getting Google user data: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return oauthUser{}, fmt.Errorf("invalid google status code %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return oauthUser{}, fmt.Errorf("error in reading Google user data: %w", err)
	}

	var _googleResponse googleResponse
	if err := json.Unmarshal(body, &_googleResponse); err != nil {
		return oauthUser{}, fmt.Errorf("error in unmarshalling Google user data: %w", err)
	}

	return _googleResponse.user(), nil
}
