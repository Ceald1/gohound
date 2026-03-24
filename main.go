package main

import (
	"fmt"
	"os"

	CLI "github.com/Ceald1/gohound/cli"
	"github.com/Ceald1/gohound/collection"
	ldap "github.com/Ceald1/gohound/ldap"
	"github.com/TheManticoreProject/gopengraph/edge"
	"github.com/TheManticoreProject/gopengraph/node"
	"github.com/charmbracelet/log"
)

func main() {
	result, err := CLI.Run()
	if err != nil {
		log.Fatal(err)
		return
	}

	l, err := ldap.NewClient(result)
	if err != nil {
		log.Fatal(err)
	}
	graph := collection.NewGraph()
	objs := collection.Search(l, result.Domain)
	nodes := collection.CreateNodes(objs)
	edges := collection.GetSecurityDescriptors(nodes)
	edges = append(edges, collection.MemberOf(nodes)...)
	edges = append(edges, collection.OUsAndContainers(nodes)...)
	edges = append(edges, collection.Delegations(nodes)...)
	edges = append(edges, collection.GMSAs(nodes)...)

	nodes = collection.CleanNodes(nodes, l)

	var invalidNodes []*node.Node
	for _, node := range nodes {
		validate := graph.AddNode(node)
		if !validate {
			invalidNodes = append(invalidNodes, node)
			// log.Warn(fmt.Sprintf("could not add node! ID: %v Name: %v", node.GetID(), node.GetProperty("name")))
		}
	}
	log.Warn(fmt.Sprintf("failed to add: %v/%v nodes", len(invalidNodes), len(nodes)))
	var invalid []*edge.Edge
	for _, edge := range edges {
		validate := graph.AddEdge(edge)
		if !validate {
			invalid = append(invalid, edge)
		}
	}

	log.Warn(fmt.Sprintf("Failed to add %v/%v edges", len(invalid), len(edges)))
	js, err := graph.ExportJSON(false)
	if err != nil {
		log.Fatal(err)
	}
	file, _ := os.Create("export.json")
	file.Write([]byte(js))
	file.Close()
}
