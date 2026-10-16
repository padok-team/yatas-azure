package internal

import "strings"

func lower(s string) string { return strings.ToLower(s) }

// ResourceGroupOf extracts the (lower-cased) resource group of an ARM resource ID.
func ResourceGroupOf(resourceID string) string {
	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return lower(parts[i+1])
		}
	}
	return ""
}

// ResourceNameOf returns the last segment of an ARM resource ID.
func ResourceNameOf(resourceID string) string {
	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	return parts[len(parts)-1]
}

// SubscriptionScope returns the ARM scope string of a subscription.
func SubscriptionScope(subscriptionID string) string {
	return "/subscriptions/" + subscriptionID
}
