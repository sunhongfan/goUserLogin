// Package goUserLogin 提供用户认证方法，包括基于文件的认证和基于 LDAP 的认证。
package goUserLogin

// UserLoginInfo 表示用户的登录信息。
type UserLoginInfo struct {
	Username string
	Password string
	AuthType AuthType
}

// Authenticator 是一个接口，定义了认证用户的方法。
type Authenticator interface {
	Authenticate(u *UserLoginInfo) (bool, error)
}

// AuthType 表示要使用的认证类型。
type AuthType string

const (
	// FileAuth 表示基于文件的认证。
	FileAuth AuthType = "file"

	// LdapAuth 表示基于 LDAP 的认证。
	LdapAuth AuthType = "ldap"
)
