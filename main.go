package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Event struct {
	Timestamp int    `json:"timestamp"`
	Event     string `json:"event"`
	Address   string `json:"address"`
	Size      int    `json:"size"`
	Comm      string `json:"comm"`
	Pid       int    `json:"pid"`
	Duration  int    `json:"duration"`
}

type metrics struct {
	sizeBytes  *prometheus.HistogramVec
	durationMs *prometheus.HistogramVec
}

func main() {
	reg := prometheus.NewRegistry()
	m := &metrics{
		sizeBytes: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "allocation_size_bytes",
			},
			[]string{"event", "comm"},
		),
		durationMs: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "allocation_duration_milliseconds",
			},
			[]string{"event", "comm"},
		),
	}
	reg.MustRegister(m.sizeBytes)
	reg.MustRegister(m.durationMs)

	go func() {
		cmd := exec.Command("./mallocsnoop")
		stdout, _ := cmd.StdoutPipe()
		err := cmd.Start()
		if err != nil {
			panic(err)
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			var event Event
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				panic(err)
			}
			m.sizeBytes.WithLabelValues(event.Event, event.Comm).Observe(float64(event.Size))
			m.durationMs.WithLabelValues(event.Event, event.Comm).Observe(float64(event.Duration))
		}
		cmd.Wait()
	}()

	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
