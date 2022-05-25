
binfile = uridecoder_linux
LDFLAGS = '-w -extldflags "-static"'

all:	amd64 arm arm64

amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ${binfile} ${LDFALGS} && mv ./${binfile} ./${binfile}_amd64

arm:
	GOOS=linux GOARCH=arm GOARM=5 go build -o ${binfile} && upx -9 ${binfile} && mv ./${binfile} ./${binfile}_armv5
	GOOS=linux GOARCH=arm GOARM=7 go build -o ${binfile} && upx -9 ${binfile} && mv ./${binfile} ./${binfile}_armv7
arm64:
	GOOS=linux GOARCH=arm64 go build -o ${binfile} && upx -9 ${binfile} && mv ./${binfile} ./${binfile}_armv8

clean:
	rm -f ${binfile}_a*

