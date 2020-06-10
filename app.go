package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/buger/goterm"
	"github.com/mdlayher/netlink"
)

const netlinkTest = 17
const magicNumber = "rainhurt"
const magicNumberResp = "phpisbst"
const magicNumberEnd = "seeunext"

var donec = make(chan string, 1)
var done = false
var testCnt = 0
var testTot = 0

type ncpMsg struct {
	saddr uint32
	sport uint16
	daddr uint32
	dport uint16
	proto uint8
}

func parseIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func parseProto(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

// send message, when isret=true, expect kernel response
func request(c *netlink.Conn, msg string, isret bool) string {
	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request,
		},
		Data: []byte(msg),
	}

	var ret netlink.Message
	var rsp []netlink.Message
	var err error
	if isret {
		rsp, err = c.Execute(req)
		ret = rsp[0]
	} else {
		ret, err = c.Send(req)
	}
	if err != nil {
		fmt.Printf("failed to send request: %v\n", err)
		return ""
	}
	return string(ret.Data)
}

func recv(c *netlink.Conn) (string, int) {
	var ret string
	cnt := 0

	tmp, err := c.Receive()
	if err != nil && !done {
		fmt.Printf("failed to receive request: %v\n", err)
		return "", 0
	}
	if done && err != nil {
		return "", 0
	}
	msg := tmp[0]
	if len(msg.Data) == len(magicNumberEnd) && string(msg.Data) == magicNumberEnd {
		return magicNumberEnd, 0
	}
	for i := 0; i < len(msg.Data); i += int(unsafe.Sizeof(ret)) {
		res := (*ncpMsg)(unsafe.Pointer(&msg.Data[i]))
		ret += fmt.Sprintf("%v %v %v %v %v\n", parseIP(res.saddr), res.sport, parseIP(res.daddr), res.dport, parseProto(res.proto))
		cnt++
	}
	return ret, cnt
}

// setup connection(magic number check)
func setup(c *netlink.Conn) bool {
	return request(c, magicNumber, true) == magicNumberResp
}

func signalHandler(c *netlink.Conn) {
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-s
		done = true
		c.SetReadDeadline(time.Unix(0, 1)) // go package bug, set ddl to unlock mux
		request(c, magicNumberEnd, false)
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		msg, _ := recv(c)
		donec <- msg
	}()
}

func testCount() {
	width := goterm.Width()
	top := 0
	for {
		if testCnt > top {
			top = testCnt
		}
		s := fmt.Sprintf("Speed: %v/s Total: %v Top: %v/s", testCnt, testTot, top)
		s += strings.Repeat(" ", width-len(s))
		fmt.Print(s + "\r")
		testCnt = 0
		time.Sleep(time.Second)
	}
}

func main() {
	var display bool
	var filename string
	var iobuf int
	flag.StringVar(&filename, "f", "ncp.log", "file to save")
	flag.BoolVar(&display, "v", false, "Display output")
	flag.IntVar(&iobuf, "b", 524288, "io buffer")
	flag.Parse()

	fmt.Println("Capture started.")
	c, err := netlink.Dial(netlinkTest, nil)
	if err != nil {
		log.Fatalf("failed to dial netlink: %v", err)
	}
	defer c.Close()

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed open file: %v", err)
	}
	defer f.Close()

	signalHandler(c)
	if !display {
		go testCount()
	}

	if !setup(c) {
		log.Fatalf("failed connect to kernel")
	}

	w := bufio.NewWriterSize(f, iobuf) // 512K buffer
	defer w.Flush()

	for msg, cnt := recv(c); !done && msg != magicNumberEnd; msg, cnt = recv(c) {
		if display {
			fmt.Println(msg)
		}
		if _, err = w.WriteString(msg); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		testCnt += cnt
		testTot += cnt
	}
	if done {
		remain := <-donec
		if remain != magicNumberEnd {
			if display {
				fmt.Println(remain)
			}
			if _, err = w.WriteString(remain); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		}
	}
	fmt.Println("Server shutdown")
}
