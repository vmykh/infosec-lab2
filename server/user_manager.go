package server

import (
	"strings"
	"fmt"
	"strconv"
)

type user struct {
	login string
	password string
	isAdmin bool
	isBanned bool
}

type userManager interface {
	getAllUsers() []user
	//userExists(login string) bool
	//getUserPassword(login string) string
	//isAdmin(login user)
	//isBanned(login user)



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
		line := fmt.Sprintf("%s;%s;%t;%t", user.login, user.password, user.isAdmin, user.isBanned)
		output += line + "\n"
	}
	return output
}
