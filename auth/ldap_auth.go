package auth

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/sunhongfan/goUserLogin"
)

// LDAPAuthenticator 实现了基于 LDAP 的认证。
type LDAPAuthenticator struct {
	Server     string
	Port       int
	BaseDN     string
	AdminDN    string
	AdminPW    string
	SearchRule string
}

// NewLDAPAuthenticator 创建一个新的 LDAPAuthenticator 实例。
func NewLDAPAuthenticator(server string, port int, baseDN, adminDN, adminPW, searchRule string) (*LDAPAuthenticator, error) {
	auth := &LDAPAuthenticator{
		Server:     server,
		Port:       port,
		BaseDN:     baseDN,
		AdminDN:    adminDN,
		AdminPW:    adminPW,
		SearchRule: searchRule,
	}

	_, err := auth.ConnLdap()
	if err != nil {
		return nil, err
	}

	return auth, nil
}

// ConnLdap 用于返回一个 Ldap Conn, 同时可以验证 Ldap 是否可达.
func (auth *LDAPAuthenticator) ConnLdap() (*ldap.Conn, error) {
	// 尝试连接到 LDAP 服务器
	ldapURL := fmt.Sprintf("ldap://%s:%d", auth.Server, auth.Port)
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Authenticate 验证用户名和密码。
func (auth *LDAPAuthenticator) Authenticate(u *goUserLogin.UserLoginInfo) (bool, error) {
	conn, err := auth.ConnLdap()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	err = conn.Bind(auth.AdminDN, auth.AdminPW)
	if err != nil {
		return false, err
	}

	searchRequest := ldap.NewSearchRequest(
		auth.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(auth.SearchRule, u.Username),
		[]string{},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return false, err
	}

	if len(sr.Entries) != 1 {
		return false, errors.New("用户不存在")
	}

	err = conn.Bind(sr.Entries[0].DN, u.Password)
	if err != nil {
		return false, errors.New("用户密码验证失败")
	}

	return true, nil
}
