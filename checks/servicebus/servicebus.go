package servicebus

import (
	"context"
	"regexp"
	"strconv"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// RetentionID is the check's unique, stable ID.
const RetentionID = "AZURE_SB_001"

// maxRetentionDays mirrors the AWS SQS rule: messages are kept at most 14 days.
const maxRetentionDays = 14

// Queue is a Service Bus queue.
type Queue struct {
	ID   string
	Name string
	// TTLDays is the default message time to live in days (ISO-8601 duration).
	TTLDays float64
}

var isoDuration = regexp.MustCompile(`^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?)?$`)

// parseTTLDays converts an ISO-8601 duration ("P14D", "PT1H"...) to days. Unknown
// formats return a huge value so the check fails instead of passing silently.
func parseTTLDays(d string) float64 {
	m := isoDuration.FindStringSubmatch(d)
	if m == nil {
		return 1e9
	}
	f := func(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v }
	return f(m[1]) + f(m[2])/24 + f(m[3])/1440 + f(m[4])/86400
}

// GetQueues lists the queues of every Service Bus namespace of the target.
func GetQueues(s internal.Session) ([]Queue, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	namespaces, err := armservicebus.NewNamespacesClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	queues, err := armservicebus.NewQueuesClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var out []Queue
	nsPager := namespaces.NewListPager(nil)
	for nsPager.More() {
		nsPage, err := nsPager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, ns := range nsPage.Value {
			nsID := internal.Deref(ns.ID)
			if !s.Target.InScope(nsID) {
				continue
			}
			qPager := queues.NewListByNamespacePager(internal.ResourceGroupOf(nsID), internal.Deref(ns.Name), nil)
			for qPager.More() {
				qPage, err := qPager.NextPage(context.TODO())
				if err != nil {
					return nil, err
				}
				for _, q := range qPage.Value {
					if q.Properties == nil {
						continue
					}
					out = append(out, Queue{
						ID:      internal.Deref(q.ID),
						Name:    internal.Deref(ns.Name) + "/" + internal.Deref(q.Name),
						TTLDays: parseTTLDays(internal.Deref(q.Properties.DefaultMessageTimeToLive)),
					})
				}
			}
		}
	}
	return out, nil
}

// checkIfRetention (≈ AWS "SQS message retention is 14 days or less").
func checkIfRetention(cfg commons.CheckConfig, in internal.Fetched[Queue], id string) {
	check := internal.NewCheck("Service Bus queues retain messages at most 14 days", "Check that the default message time to live of queues is 14 days or less", id, "Security", "Good Practice")
	internal.Evaluate(cfg, check, in, "Service Bus queues", func(q Queue) *internal.Verdict {
		if q.TTLDays > maxRetentionDays {
			return internal.No(q.ID, "Queue "+q.Name+" keeps messages more than 14 days")
		}
		return internal.Yes(q.ID, "Queue "+q.Name+" keeps messages 14 days or less")
	})
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetQueues(s)
	queues := internal.Fetch("Service Bus queues", list, err)
	internal.RunCategory("SB", c, queue, internal.Bind(RetentionID, queues, checkIfRetention))
}
