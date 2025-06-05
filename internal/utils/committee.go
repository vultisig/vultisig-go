package utils

// CombineCommittees merges old and new committee members, removing duplicates
func CombineCommittees(oldCommittee, newCommittee []string) []string {
	// Create a set to avoid duplicates
	seen := make(map[string]bool)
	var combined []string

	// Add all parties from both committees
	for _, party := range oldCommittee {
		if !seen[party] {
			combined = append(combined, party)
			seen[party] = true
		}
	}
	for _, party := range newCommittee {
		if !seen[party] {
			combined = append(combined, party)
			seen[party] = true
		}
	}

	return combined
}

// GetCommitteeIndices returns the indices of old and new committee members in the combined list
func GetCommitteeIndices(allCommittee, oldCommittee, newCommittee []string) ([]int, []int) {
	var oldIndices, newIndices []int

	for i, party := range allCommittee {
		for _, oldParty := range oldCommittee {
			if party == oldParty {
				oldIndices = append(oldIndices, i)
				break
			}
		}
		for _, newParty := range newCommittee {
			if party == newParty {
				newIndices = append(newIndices, i)
				break
			}
		}
	}

	return oldIndices, newIndices
}