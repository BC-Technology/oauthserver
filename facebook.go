package oauthserver

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func getFacebookUserData(accessToken string) (User, error) {
	response, err := http.Get(fmt.Sprintf("https://graph.facebook.com/me?access_token=%s&format=json&fields=name,email", accessToken))
	if err != nil {
		return User{}, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return User{}, fmt.Errorf("invalid facebook status code %d", response.StatusCode)
	}

	var oauthUserData facebookResponse
	if err := json.NewDecoder(response.Body).Decode(&oauthUserData); err != nil {
		return User{}, err
	}

	if oauthUserData.Error.Message != "" {
		return User{}, fmt.Errorf(oauthUserData.Error.Message)
	}

	return oauthUserData.user(), nil
}
