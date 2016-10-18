package server

import "testing"

func Test_itShouldProperlyParseRawData(t *testing.T) {
	// arrange
	rawData := "  # some comments\n\n\n" +
		"admin;pass;true;false\n" +
		"john;abc;false;false\n" +
		"#another comment\n" +
		"lukas;12345;false;true\n\n"


	// act
	parsedUsers := parseUsers(rawData)

	// assert
	if len(parsedUsers) != 3 {
		t.Error("amount of parse users is wrong")
	}
	expectedUsers := []user{
		{"admin", "pass", true, false},
		{"john", "abc", false, false},
		{"lukas", "12345", false, true},
	}
	for i, _ := range parsedUsers {
		if (parsedUsers[i] != expectedUsers[i]) {
			t.Errorf("parsed user #%d is wrong", i)
		}
	}
}

func Test_itShouldProperlyExportUsers(t *testing.T) {
	// arrange
	users := []user{
		{"admin", "pass", true, false},
		{"larry", "123", false, false}}


	// act
	exported := exportUsers(users)

	// assert
	expected := "# login;password;is_admin;is_banned\n\n" +
		"admin;pass;true;false\n" +
		"larry;123;false;false\n";
	if (exported != expected) {
		t.Fail()
	}
}

//func
