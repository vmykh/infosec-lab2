package server

import (
	"strings"
	"fmt"
	"strconv"
	"sync"
	"errors"
)

type user struct {
	Login string
	Password string
	IsAdmin bool
	IsBanned bool
}

type userManager interface {
	GetUser(login string) (user, error)
	UpdateUser(updUser user) error
	AddUser(newUser user) error
}

type userManagerState struct {
	users map[string]user
	mutex *sync.Mutex
}

// TODO(vmykh): check whether object from map are copied
func (ums *userManagerState) GetUser(login string) (user, error) {
	ums.mutex.Lock()

	usr, ok := ums.users[login]

	ums.mutex.Unlock()

	if !ok {
		return user{}, errors.New("no such user")
	}
	return usr, nil
}

// TODO(vmykh): check whether object from map are copied
func (ums *userManagerState) UpdateUser(updUser user) error {
	ums.mutex.Lock()

	_, ok := ums.users[updUser.Login]
	if !ok {
		// TODO(vmykh): make more informative error message (at least include login)
		return errors.New("user does not exist")
	}
	ums.users[updUser.Login] = updUser

	ums.mutex.Unlock()

	return nil
}

func (ums *userManagerState) AddUser(newUser user) error {
	ums.mutex.Lock()

	_, ok := ums.users[newUser.Login]
	if ok {
		return errors.New("such user already exist")
	}
	ums.users[newUser.Login] = newUser

	ums.mutex.Unlock()

	return nil
}

func createUserManager(users []user) userManager {
	userMap := make(map[string]user)
	for _, usr := range users {
		userMap[usr.Login] = usr
	}

	return &userManagerState{userMap, &sync.Mutex{}}
}

func parseUsers(rawData string) []user {
	lines := strings.Split(rawData, "\n")
	users := make([]user, 0, 0)
	for _, line := range lines {
		trimmedLine := strings.Trim(line, " \t")
		if len(trimmedLine) == 0 {
			continue
		}
		if strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		userFields := strings.Split(trimmedLine, ";")
		if len(userFields) != 4 {
			fmt.Printf("Line is invalid: %s", line)
			continue
		}

		isAdmin, err := strconv.ParseBool(userFields[2])
		if (err != nil) {
			fmt.Printf("Line is invalid: %s", line)
			continue
		}

		isBanned, err := strconv.ParseBool(userFields[3])
		if (err != nil) {
			fmt.Printf("Line is invalid: %s", trimmedLine)
			continue
		}
		users = append(users, user{
			userFields[0],
			userFields[1],
			isAdmin,
			isBanned})
	}

	return users
}

func exportUsers(users []user) string {
	header := "# login;password;is_admin;is_banned"
	output := header + "\n\n"
	for _, user := range users {
		line := fmt.Sprintf("%s;%s;%t;%t", user.Login, user.Password, user.IsAdmin, user.IsBanned)
		output += line + "\n"
	}
	return output
}
