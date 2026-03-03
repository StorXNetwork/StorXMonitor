##@ Tooling

.PHONY: archview/svg
archview/svg: ## Create SVG diagrams using archview
	archview -root "github.com/StorXNetwork/StorXMonitor/satellite.Core"     -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/satellite/ ./satellite/... | dot -T svg -o satellite-core.svg
	archview -root "github.com/StorXNetwork/StorXMonitor/satellite.API"      -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/satellite/ ./satellite/... | dot -T svg -o satellite-api.svg
	archview -root "github.com/StorXNetwork/StorXMonitor/satellite.Repairer" -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/satellite/ ./satellite/... | dot -T svg -o satellite-repair.svg
	archview -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/satellite/   ./satellite/...   | dot -T svg -o satellite.svg
	archview -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/storagenode/ ./storagenode/... | dot -T svg -o storage-node.svg

.PHONY: archview/graphml
archview/graphml: ## Create graphml diagrams using archview
	archview -root "github.com/StorXNetwork/StorXMonitor/satellite.Core"     -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/satellite/ -out satellite-core.graphml   ./satellite/...
	archview -root "github.com/StorXNetwork/StorXMonitor/satellite.API"      -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/satellite/ -out satellite-api.graphml    ./satellite/...
	archview -root "github.com/StorXNetwork/StorXMonitor/satellite.Repairer" -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/satellite/ -out satellite-repair.graphml ./satellite/...
	archview -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/satellite/   -out satellite.graphml    ./satellite/...
	archview -skip-class "Peer,Master Database" -trim-prefix github.com/StorXNetwork/StorXMonitor/storagenode/ -out storage-node.graphml ./storagenode/...
