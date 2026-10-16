default: build

test:
	go test ./...

build:
	go build -o bin/yatas-azure

update:
	go get -u
	go mod tidy

install: build
	mkdir -p ~/.yatas.d/plugins/github.com/padok-team/yatas-azure/local/
	mv ./bin/yatas-azure ~/.yatas.d/plugins/github.com/padok-team/yatas-azure/local/

release: test
	npm run release
	git push --follow-tags origin main