package auth

import (
	"encoding/json"
	"errors"
	"github.com/sunhongfan/goUserLogin"
	"os"
)

// FileAuthenticator 实现了基于文件的认证。
type FileAuthenticator struct {
	filePath  string
	userField string
	passField string
	users     map[string]string
}

// NewFileAuthenticator 创建一个新的 FileAuthenticator 实例。
func NewFileAuthenticator(filePath string, userField, passField string) (*FileAuthenticator, error) {
	auth := &FileAuthenticator{
		filePath:  filePath,
		userField: userField,
		passField: passField,
		users:     make(map[string]string),
	}

	if err := auth.loadUsers(); err != nil {
		return nil, err
	}

	return auth, nil
}

// loadUsers 加载用户信息文件。
func (auth *FileAuthenticator) loadUsers() error {
	data, err := os.ReadFile(auth.filePath)
	if err != nil {
		return err
	}

	var users []map[string]string
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}

	for _, user := range users {
		username := user[auth.userField]
		password := user[auth.passField]
		auth.users[username] = password
	}
	return nil
}

// Authenticate 验证用户名和密码。
func (auth *FileAuthenticator) Authenticate(u *goUserLogin.UserLoginInfo) (bool, error) {
	if storedPass, ok := auth.users[u.Username]; ok && storedPass == u.Password {
		return true, errors.New("用户名或密码错误")
	}
	return false, nil
}
