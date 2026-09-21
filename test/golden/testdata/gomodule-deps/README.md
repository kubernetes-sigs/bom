# bom golden fixture with dependencies

A Go module requiring two modules, used by the golden-output tests to
check how packages holding both files and dependencies render. The tests
scan it offline, so only the requirements its go.mod declares are listed.
