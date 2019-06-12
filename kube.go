package main

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

type KubeConfig struct {
	Kind           string           `yaml:"kind"`
	Preferences    Preferences      `yaml:"preferences"`
	CurrentContext string           `yaml:"current-context"`
	Contexts       []ContextElement `yaml:"contexts"`
	Clusters       []ClusterElement `yaml:"clusters"`
	APIVersion     string           `yaml:"apiVersion"`
	Users          []UserElement    `yaml:"users"`
}

type ClusterElement struct {
	Cluster ClusterCluster `yaml:"cluster"`
	Name    string         `yaml:"name"`
}

type ClusterCluster struct {
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	Server                   string `yaml:"server"`
}

type ContextElement struct {
	Name    string         `yaml:"name"`
	Context ContextContext `yaml:"context"`
}

type ContextContext struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

type Preferences struct {
}

type UserElement struct {
	Name string   `yaml:"name"`
	User UserUser `yaml:"user"`
}

type UserUser struct {
	Token string `yaml:"token"`
}

func genKubeConfig(token string, clusterResponse *ClusterResponse) ([]byte, error) {
	name := fmt.Sprintf("gke_%s_%s_%s", *projectID, *locationID, *clusterID)
	kc := &KubeConfig{
		Kind:           "Config",
		Preferences:    Preferences{},
		CurrentContext: name,
		Contexts: []ContextElement{
			{
				Name: name,
				Context: ContextContext{
					Cluster: name,
					User:    name,
				},
			},
		},
		Clusters: []ClusterElement{
			{
				Cluster: ClusterCluster{
					CertificateAuthorityData: clusterResponse.MasterAuth.ClusterCACertificate,
					Server:                   "https://" + clusterResponse.Endpoint,
				},
				Name: name,
			},
		},
		APIVersion: "v1",
		Users: []UserElement{
			{
				Name: name,
				User: UserUser{
					Token: token,
				},
			},
		},
	}
	return yaml.Marshal(kc)
}
