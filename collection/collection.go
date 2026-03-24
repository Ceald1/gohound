package collection

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	gohoundLdap "github.com/Ceald1/gohound/ldap"
	"github.com/TheManticoreProject/gopengraph"
	"github.com/TheManticoreProject/gopengraph/edge"
	"github.com/TheManticoreProject/gopengraph/node"
	"github.com/TheManticoreProject/gopengraph/properties"
	"github.com/charmbracelet/log"
	"github.com/go-ldap/ldap/v3"
	parser "github.com/huner2/go-sddlparse/v2"
)

type SDFlagsRequestValue struct {
	Flags int
}

func NewSDControl() (control *ldap.ControlString, err error) {
	value, err := asn1.Marshal(SDFlagsRequestValue{
		Flags: 0x07, // OWNER | GROUP | DACL
	})
	if err != nil {
		return
	}
	control = &ldap.ControlString{
		ControlType:  "1.2.840.113556.1.4.801",
		Criticality:  true,
		ControlValue: string(value), // IMPORTANT: must be string
	}
	return
}

func bytesToSidString(sidBytes []byte) string {
	if len(sidBytes) < 8 {
		return ""
	}
	revision := sidBytes[0]
	subCount := sidBytes[1]
	authority := uint64(0)
	for i := 2; i < 8; i++ {
		authority |= uint64(sidBytes[i]) << (8 * (5 - (i - 2)))
	}

	sidStr := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < int(subCount); i++ {
		offset := 8 + i*4
		if offset+4 > len(sidBytes) {
			break
		}
		sub := binary.LittleEndian.Uint32(sidBytes[offset : offset+4])
		sidStr += fmt.Sprintf("-%d", sub)
	}
	return sidStr
}

var (
	SPNs    = map[string]string{}
	Members = map[string]string{}
	SDDLs   = map[string]parser.SDDL{}
	baseDN  = ""
)

func NewGraph() (graph *gopengraph.OpenGraph) {
	return gopengraph.NewOpenGraph("Base")
}

func BaseDNGen(domain string) (baseDN string) {
	split := strings.Split(domain, ".")
	for i, s := range split {
		split[i] = fmt.Sprintf("dc=%s", s)
	}
	baseDN = strings.Join(split, ",")
	return
}

type LdapObject struct {
	ID         string         // SID
	Properties map[string]any // All properties
	Kind       string         // object class that matches the kind
}

func Search(l ldap.Client, domain string) (results []LdapObject) {
	baseDN = BaseDNGen(domain)
	filter := "(objectClass=*)"
	control, _ := NewSDControl()
	searchReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree,
		0, 0, 0,
		false, filter, []string{}, []ldap.Control{control})

	entries, err := l.Search(searchReq)
	if err != nil {
		log.Fatal(err)
		return
	}
	for _, result := range entries.Entries {
		objClasses := result.GetAttributeValues("objectClass")
		obj := LdapObject{}
		for _, objClass := range objClasses {
			objClass = strings.ToLower(objClass)
			switch objClass {
			case "user":
				obj.Kind = "User"
			case "computer":
				obj.Kind = "Computer"
			case "group":
				obj.Kind = "Group"
			case "domain":
				obj.Kind = "Domain"
			case "gpo":
				obj.Kind = "GPO"
			case "ou", "organizationalunit":
				obj.Kind = "OU"
			case "container":
				obj.Kind = "Container"
			case "certtemplate":
				obj.Kind = "CertTemplate"
			case "enterpriseca":
				obj.Kind = "EnterpriseCA"
			case "rootca":
				obj.Kind = "RootCA"
			case "aiaca":
				obj.Kind = "AIACA"
			case "ntauthstore":
				obj.Kind = "NTAuthStore"
			case "issuancecpolicy":
				obj.Kind = "IssuancePolicy"
			case "adlocalgroup":
				obj.Kind = "ADLocalGroup"
			case "base":
				obj.Kind = "Base"
			case strings.ToLower("pKICertificateTemplate"):
				obj.Kind = "CertTemplate"
			case strings.ToLower("pKIEnrollmentService"):
				obj.Kind = "RootCA"
			}
		}
		if obj.Kind == "" {
			continue
		}
		obj.ID = bytesToSidString(result.GetRawAttributeValue("objectSid"))
		obj.Properties = ExtractAttributes(result)
		//		for _, attr := range result.Attributes {
		//			obj.Properties[attr.Name] = attr.Values
		//		}

		results = append(results, obj)

	}
	results = append(results, AddWellKnownSIDs(results)...)

	return
}

func AddWellKnownSIDs(results []LdapObject) []LdapObject {
	existingSIDs := make(map[string]bool)

	// Track which SIDs already exist
	for _, obj := range results {
		existingSIDs[obj.ID] = true
	}

	// Add missing well-known SIDs
	for sid, name := range WellKnownSIDs {
		if existingSIDs[sid] {
			continue // Skip if already in results
		}

		results = append(results, LdapObject{
			ID:   sid,
			Kind: "WellKnownPrincipal",
			Properties: map[string]any{
				"objectsid":   sid,
				"name":        name,
				"cn":          name,
				"displayname": name,
			},
		})
	}

	return results
}

func ExtractAttributes(entry *ldap.Entry) (result map[string]any) {
	result = make(map[string]any)

	for _, attr := range entry.Attributes {
		attr.Name = strings.ToLower(attr.Name)
		if attr.Name == "objectsid" {
			attr.Values = []string{bytesToSidString(attr.ByteValues[0])}
		}
		if len(attr.Values) > 0 {
			if len(attr.Values) == 1 {
				result[attr.Name] = attr.Values[0]
			} else {
				result[attr.Name] = attr.Values
			}
			continue
		}

		if len(attr.ByteValues) > 0 {
			if len(attr.ByteValues) == 1 {
				result[attr.Name] = attr.ByteValues[0]
			} else {
				result[attr.Name] = attr.ByteValues
			}
		}
	}
	return result
}

func CreateNodes(ldapEntries []LdapObject) (nodes []*node.Node) {
	for _, entry := range ldapEntries {
		props := properties.NewPropertiesFromMap(entry.Properties)
		node, _ := node.NewNode(entry.ID, []string{entry.Kind}, props)
		if node == nil {
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes
}

func ParseAccessMask(maskStr string) []string {
	var masks []string
	for i := 0; i < len(maskStr); i += 2 {
		if i+2 <= len(maskStr) {
			masks = append(masks, maskStr[i:i+2])
		}
	}
	return masks
}

func GetSecurityDescriptors(nodes []*node.Node) (edges []*edge.Edge) {
	for _, node := range nodes {
		descriptorsRaw := node.GetProperty("ntsecuritydescriptor")
		if descriptorsRaw == nil {
			continue
		}
		descriptorsRune := descriptorsRaw.(string)
		descriptors := []byte(descriptorsRune)
		sddl, _ := parser.SDDLFromBinary(descriptors)
		if sddl == nil { // if nothing
			continue
		}

		dacls := sddl.DACL

		for _, dacl := range dacls {
			if dacl == nil {
				continue
			}
			guid := dacl.ObjectType.String()
			extendedRight := ExtendedRights[guid]
			if extendedRight == "" {
				extendedRight = ExtendedRights[strings.ToLower(guid)]
			}
			accessMask := dacl.AccessMask.String()
			Type := dacl.Type.String()
			whiteListed := false
			for _, a := range ACETYPE {
				if a == Type {
					whiteListed = true
					break
				}
			}
			if !whiteListed {
				continue // skip
			}
			maskComponents := ParseAccessMask(accessMask)
			var mask string
			for _, m := range maskComponents {
				mask = FLAGS[m]
				if len(mask) > 2 {
					break
				}
			}
			// log.Info(fmt.Sprintf("found access mask: %s..", mask))
			if mask == "" && extendedRight == "" {
				continue
			}
			edgeName := mask
			if extendedRight != "" {
				edgeName = extendedRight
			}
			sid := dacl.SID
			match := MatchNode(nodes, "objectsid", sid)
			if match == nil {
				continue // skip
			}
			property := properties.NewProperties()
			property.SetProperty("start", match.GetID())
			property.SetProperty("end", node.GetID())
			property.SetProperty("edgeName", edgeName)
			property.SetProperty("flags", dacl.Flags.String())
			property.SetProperty("mask", dacl.AccessMask.String())
			if ExtendedRightsToBH[edgeName] == "" {
				continue
			}
			edgeName = ExtendedRightsToBH[edgeName]
			newEdge, _ := edge.NewEdge(match.GetID(), node.GetID(), edgeName, property)
			edges = append(edges, newEdge)
		}
	}
	return edges
}

func MemberOf(nodes []*node.Node) (edges []*edge.Edge) {
	for _, n := range nodes {
		membersIface := n.GetProperty("memberof")
		if membersIface == nil {
			continue
		}

		var groups []string
		if str, ok := membersIface.(string); ok {
			groups = append(groups, str)
		}
		if strs, ok := membersIface.([]string); ok {
			groups = append(groups, strs...)
		}
		for _, group := range groups {
			matched := MatchNode(nodes, "distinguishedname", group)
			if matched == nil {
				continue
			}
			start := n.GetID()
			end := matched.GetID()
			kind := "MemberOf"
			newEdge, _ := edge.NewEdge(start, end, kind, nil)
			edges = append(edges, newEdge)
		}
	}
	return
}

func OUsAndContainers(nodes []*node.Node) (edges []*edge.Edge) {
	reOU := regexp.MustCompile(`OU=[^,]+`)

	for _, n := range nodes {
		dnR := n.GetProperty("distinguishedname")
		if dnR == nil {
			continue
		}
		dn := dnR.(string)

		// Extract all OUs
		ous := reOU.FindAllString(dn, -1)
		if len(ous) == 0 {
			continue
		}

		for i, ou := range ous {
			ous[i] = strings.TrimPrefix(ou, "OU=")
		}

		parentOUForNode := ous[len(ous)-1]
		// log.Info(parentOUForNode)
		startNode := MatchNode(nodes, "name", parentOUForNode, "OU")
		if startNode == nil {
			startNode = MatchNode(nodes, "name", parentOUForNode, "Container")
		}
		if startNode == nil {
			continue
		}
		start := startNode.GetID()
		end := n.GetID()
		newEdge, _ := edge.NewEdge(start, end, "Contains", nil)
		edges = append(edges, newEdge)
		// log.Info(strings.Join(ous, " > "))
	}
	return
}

func Delegations(nodes []*node.Node) (edges []*edge.Edge) {
	for _, n := range nodes {
		AllowedToDelegateTo := n.GetProperty("msds-allowedtodelegateto")
		resourceDelegation := n.GetProperty(strings.ToLower("msDS-AllowedToActOnBehalfOfOtherIdentity"))
		var endNode *node.Node
		var newEdge *edge.Edge

		if AllowedToDelegateTo == nil && resourceDelegation == nil {
			continue
		}
		if AllowedToDelegateTo != nil {
			AllowedToDelegateToRaws := AllowedToDelegateTo.([]string) // spn
			for _, AllowedToDelegateToRaw := range AllowedToDelegateToRaws {
				endNode = MatchNode(nodes, "serviceprincipalname", AllowedToDelegateToRaw)
				propers := properties.NewProperties()
				propers.SetProperty("spn", AllowedToDelegateToRaw)
				newEdge, _ = edge.NewEdge(n.GetID(), endNode.GetID(), "AllowedToDelegate", propers)
				edges = append(edges, newEdge)
			}
		}
		if resourceDelegation != nil {
			resource, ok := resourceDelegation.(string)
			if !ok {
				continue
			}
			sddl, err := parser.SDDLFromBinary([]byte(resource))
			if err != nil {
				log.Fatal(err)
			}
			endIDItem := sddl.DACL[0]
			if endIDItem == nil {
				continue
			}
			endID := endIDItem.SID
			endNode = MatchNode(nodes, endID, "objectsid")
			if endNode == nil {
				continue
			}
			newEdge, _ = edge.NewEdge(n.GetID(), endNode.GetID(), "AllowedToAct", nil)

		}

		if endNode == nil {
			continue
		}

	}
	return edges
}

// match node based on property name and value
func MatchNode(nodes []*node.Node, key, value string, nodeType ...string) *node.Node {
	for _, node := range nodes {
		propertyRaw := node.GetProperty(key)
		if propertyRaw == nil {
			continue
		}
		property, ok := propertyRaw.(string)
		if !ok {
			// add logic for handling arrays
			property, ok := propertyRaw.([]string)
			if !ok {
				continue
			}
			for _, p := range property {
				if strings.EqualFold(p, value) {
					return node
				}
			}
		}
		if strings.EqualFold(value, property) {
			if nodeType != nil {
				if Contains(node.GetKinds(), nodeType[0]) {
					return node
				} else {
					return nil
				}
			} else {
				return node
			}
		}
	}

	return nil
}

func Contains(arr []string, target string) bool {
	for _, item := range arr {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

func CleanNodes(nodes []*node.Node, l ldap.Client) []*node.Node {
	trustedForDelegation := 0x80000
	for _, node := range nodes {
		node.RemoveProperty("ntsecuritydescriptor")
		node.RemoveProperty("msds-allowedtodelegateto")
		node.RemoveProperty("objectguid")
		userAccControl := node.GetProperty("useraccountcontrol")
		if userAccControl != nil {
			acc, err := strconv.ParseUint(userAccControl.(string), 10, 64)
			if err != nil {
				log.Fatal(err)
			}
			uacU32 := int(acc)
			isTrusted := (uacU32 & trustedForDelegation) == trustedForDelegation

			node.SetProperty("unconstraineddelegation", isTrusted)
		}
		gmsaP := node.GetProperty(strings.ToLower("msDS-ManagedPassword"))
		if gmsaP != nil {
			blob, err := gohoundLdap.ParseManagedPasswordBlob([]byte(gmsaP.(string)))
			if err != nil {
				log.Fatal(err)
			}
			password := gohoundLdap.StringToUTF16LE(string(blob.CurrentPassword))
			ntlmH := gohoundLdap.NTLMHash(string(password))
			log.Info(ntlmH)
			node.RemoveProperty(strings.ToLower("msDS-ManagedPassword"))
			node.SetProperty(strings.ToLower("msDSManagedPassword"), ntlmH)
		}

	}
	nodes = SearchLaps(nodes, l)

	return nodes
}

func SearchLaps(nodes []*node.Node, l ldap.Client) []*node.Node {
	filter := "(&(objectCategory=computer)(objectClass=*))"
	searchReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree,
		0, 0, 0,
		false, filter, []string{"objectSid", "ms-Mcs-AdmPwd"}, []ldap.Control{})

	entries, err := l.Search(searchReq)
	if err != nil {
		log.Info(err)
		return nodes
	}
	log.Info(len(entries.Entries))
	for _, entry := range entries.Entries {
		objSid := bytesToSidString(entry.GetRawAttributeValue("objectSid"))
		for _, n := range nodes {
			chal := n.GetProperty("objectsid")
			if chal == nil {
				continue
			}
			chalSid := chal.(string)
			if chalSid == objSid {
				mcsAdmPWD := hex.EncodeToString(entry.GetRawAttributeValue("ms-MCS-AdmPwd"))
				n.SetProperty("lapspassword", mcsAdmPWD)
				if mcsAdmPWD != "" {
					n.SetProperty("haslaps", true)
				} else {
					n.SetProperty("haslaps", false)
				}
			}
		}
	}
	return nodes
}

func GMSAs(nodes []*node.Node) (edges []*edge.Edge) {
	for _, n := range nodes {
		msaMemberShip := n.GetProperty(strings.ToLower("msDS-GroupMSAMembership"))
		if msaMemberShip == nil {
			continue
		}
		t := []byte(msaMemberShip.(string))
		sddl, err := parser.SDDLFromBinary(t)
		if sddl == nil {
			log.Info(err)
			continue
		}
		sourceIDs := sddl.DACL
		for _, sourceIDRaw := range sourceIDs {
			sourceID := sourceIDRaw.SID
			matched := MatchNode(nodes, "objectsid", sourceID)
			if matched == nil {
				continue
			}
			newEdge, _ := edge.NewEdge(matched.GetID(), n.GetID(), "ReadGMSAPassword", nil)
			edges = append(edges, newEdge)
		}
	}
	return edges
}
