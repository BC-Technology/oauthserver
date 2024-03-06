package oauthserver

import "fmt"

type (
	User struct {
		ProviderID string
		Email      string
		Name       string
	}
	facebookResponse struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
		Pic   struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
		Birthday string `json:"birthday"`
		Error    struct {
			Message      string `json:"message"`
			Type         string `json:"type"`
			Code         int    `json:"code"`
			ErrorSubcode int    `json:"error_subcode"`
			FBTraceID    string `json:"fbtrace_id"`
		} `json:"error"`
	}
	googleResponse struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
		Name  string `json:"name"`
	}
	Provider int
)

const (
	FacebookProvider Provider = iota
	EmailProvider
	GoogleProvider
	AppleProvider
)

func (r googleResponse) user() User {
	return User{
		Email:      r.Email,
		ProviderID: r.Sub,
		Name:       r.Name,
	}
}

func (r facebookResponse) user() User {
	return User{
		Email:      r.Email,
		ProviderID: r.ID,
		Name:       r.Name,
	}
}

func GetUserData(provider Provider, accessToken string) (User, error) {
	switch provider {
	case GoogleProvider:
		return getGoogleUserData(accessToken)
	case FacebookProvider:
		return getFacebookUserData(accessToken)
	default:
		return User{}, fmt.Errorf("provider not supported")
	}
}
