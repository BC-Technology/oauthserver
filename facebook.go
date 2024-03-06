package oauthserver

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func getFacebookUserData(accessToken string) (oauthUser, error) {
	response, err := http.Get(fmt.Sprintf("https://graph.facebook.com/me?access_token=%s&format=json&fields=name,email", accessToken))
	if err != nil {
		return oauthUser{}, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return oauthUser{}, fmt.Errorf("invalid facebook status code %d", response.StatusCode)
	}

	var oauthUserData facebookResponse
	if err := json.NewDecoder(response.Body).Decode(&oauthUserData); err != nil {
		return oauthUser{}, err
	}

	if oauthUserData.Error.Message != "" {
		return oauthUser{}, fmt.Errorf(oauthUserData.Error.Message)
	}

	return oauthUserData.user(), nil
}
